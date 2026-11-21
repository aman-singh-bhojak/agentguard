package com.agentguard.service;

import com.agentguard.dto.CheckResponse;
import com.agentguard.model.CommandLog;
import com.agentguard.parser.CommandParser;
import com.agentguard.parser.ParsedCommand;
import com.agentguard.repository.CommandLogRepository;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Core rule engine that evaluates an AI-agent command against 8
 * weighted security rules, computes a risk score (capped at 100),
 * and returns a verdict.
 * <p>
 * <b>Safety contract:</b> This class NEVER executes any command.
 * It only analyses text strings.
 * <p>
 * Decision thresholds:
 * <ul>
 *   <li>0–29  → ALLOW  (status AUTO_APPROVED)</li>
 *   <li>30–69 → NEEDS_APPROVAL (status PENDING)</li>
 *   <li>70–100 → DENY  (status BLOCKED)</li>
 * </ul>
 */
@Service
public class RuleEngineService {

    private final CommandParser commandParser;
    private final CommandLogRepository commandLogRepository;

    // ═══════════════════════════════════════════════════════════
    //  RULE WEIGHTS  (tune here or move to a config file later)
    // ═══════════════════════════════════════════════════════════

    private static final int W_PROTECTED_PATH   = 40;   // Rule 1
    private static final int W_DESTRUCTIVE       = 55;   // Rule 2
    private static final int W_PRIV_ESCALATION   = 35;   // Rule 3
    private static final int W_DATA_EXFIL        = 35;   // Rule 4
    private static final int W_DOWNLOAD_EXEC     = 50;   // Rule 5
    private static final int W_SYSTEM_MODIFY     = 20;   // Rule 6
    private static final int W_OBFUSCATION       = 25;   // Rule 7
    private static final int W_CHAINING          = 10;   // Rule 8

    // ═══════════════════════════════════════════════════════════
    //  COMPILED REGEX PATTERNS  (created once, reused forever)
    // ═══════════════════════════════════════════════════════════

    // Rule 1 — Protected path targeted (+40)
    //   C:\, /, /etc, /boot, System32, ~/.ssh …
    private static final Pattern PROTECTED_PATH = Pattern.compile(
            "\\b[a-z]:(?:[\\\\/ ]|$)|" +                                      // Windows drive root
            "(?:^|\\s)/(?:\\s|$|\\*)|" +                                       // standalone / (root)
            "/(?:etc|boot|root|usr|bin|sbin|var|dev|proc|sys)(?:/|\\s|$)|" +   // Unix system dirs
            "\\bsystem32\\b|" +                                                // Windows System32
            "\\.ssh(?:/|\\s|$)"                                                // SSH directory
    );

    // Rule 2 — Destructive command (+55)
    //   format, rm -rf, del /s, mkfs, dd …
    private static final Pattern DESTRUCTIVE_CMD = Pattern.compile(
            "\\bformat\\b|" +
            "\\brm\\s+-\\w*[rf]|" +           // rm -rf, rm -r, rm -f, rm -fr
            "\\bdel\\s+/[sfq]|" +             // del /s, del /f, del /q
            "\\bmkfs\\b|" +
            "\\bdd\\s+if=|" +                 // dd if=…
            "\\bfdisk\\b|" +
            "\\bwipefs\\b|" +
            "\\bshred\\b|" +
            "\\bdiskpart\\b|" +
            "\\brmdir\\s+/[sq]"               // rmdir /s /q
    );

    // Rule 3 — Privilege escalation (+35)
    //   sudo, runas, su, chmod 777 …
    private static final Pattern PRIV_ESCALATION = Pattern.compile(
            "\\bsudo\\b|" +
            "\\brunas\\b|" +
            "\\bsu\\b|" +
            "\\bdoas\\b|" +
            "\\bchmod\\s+(?:777|666|\\+s|4[0-7]{3})|" +   // risky permission modes
            "\\bchown\\s+root\\b"
    );

    // Rule 4 — Data exfiltration (+35)
    //   curl/wget/scp/nc sending files to external hosts
    private static final Pattern DATA_EXFIL = Pattern.compile(
            "\\bcurl\\b.*(?:\\s-[dFT]\\b|--data|--upload)|" +   // curl with data-sending flags
            "\\bwget\\b.*--post|" +                              // wget POST
            "\\bscp\\b|" +                                       // any scp usage
            "\\b(?:nc|netcat|ncat)\\b"                           // netcat (suspicious)
    );

    // Rule 5 — Download-and-execute (+50)
    //   curl … | sh, powershell iex …
    private static final Pattern DOWNLOAD_EXEC = Pattern.compile(
            "\\b(?:curl|wget)\\b.*\\|.*\\b(?:ba)?sh\\b|" +       // curl/wget piped to sh/bash
            "\\b(?:curl|wget)\\b.*\\|.*\\bpython\\b|" +           // piped to python
            "\\bpowershell\\b.*\\biex\\b|" +                      // PowerShell IEX
            "\\binvoke-expression\\b|" +
            "\\binvoke-webrequest\\b.*\\|.*\\biex\\b"
    );

    // Rule 6 — System modification (+20)
    //   package install, service stop, registry edit, new user, shutdown …
    private static final Pattern SYS_MODIFY = Pattern.compile(
            "\\b(?:apt|apt-get|yum|dnf|pacman|zypper|apk|brew|choco|winget|pip|npm)\\s+install\\b|" +
            "\\bservice\\s+\\w+\\s+(?:stop|start|restart)\\b|" +
            "\\bsystemctl\\s+(?:stop|start|restart|disable|enable)\\b|" +
            "\\breg\\s+(?:add|delete)\\b|" +
            "\\b(?:useradd|adduser|userdel|deluser|usermod)\\b|" +
            "\\b(?:shutdown|reboot|poweroff|halt)\\b|" +
            "\\binit\\s+[06]\\b|" +
            "\\bcrontab\\b"
    );

    // Rules 7 & 8 use ParsedCommand flags directly (no extra regex).

    // ═══════════════════════════════════════════════════════════
    //  CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════

    public RuleEngineService(CommandParser commandParser,
                             CommandLogRepository commandLogRepository) {
        this.commandParser        = commandParser;
        this.commandLogRepository = commandLogRepository;
    }

    // ═══════════════════════════════════════════════════════════
    //  PUBLIC API
    // ═══════════════════════════════════════════════════════════

    /**
     * Evaluate a raw command string against all 8 rules,
     * persist the result to the database, and return a
     * {@link CheckResponse}.
     */
    public CheckResponse evaluate(String rawCommand) {

        // ── 1. Parse ────────────────────────────────────────────
        ParsedCommand parsed = commandParser.parse(rawCommand);
        String       norm = parsed.getNormalizedCommand();
        List<String> subs = parsed.getSubCommands();

        int           score        = 0;
        List<String>  matchedRules = new ArrayList<>();
        List<String>  reasons      = new ArrayList<>();

        // ── 2. Evaluate each rule ───────────────────────────────

        // Rule 1 — Protected path
        if (matchesAny(PROTECTED_PATH, norm, subs)) {
            score += W_PROTECTED_PATH;
            matchedRules.add("PROTECTED_PATH");
            reasons.add("Targets a protected system path");
        }

        // Rule 2 — Destructive command
        if (matchesAny(DESTRUCTIVE_CMD, norm, subs)) {
            score += W_DESTRUCTIVE;
            matchedRules.add("DESTRUCTIVE_COMMAND");
            reasons.add("Uses a destructive command");
        }

        // Rule 3 — Privilege escalation
        if (matchesAny(PRIV_ESCALATION, norm, subs)) {
            score += W_PRIV_ESCALATION;
            matchedRules.add("PRIVILEGE_ESCALATION");
            reasons.add("Attempts privilege escalation");
        }

        // Rule 4 — Data exfiltration
        if (matchesAny(DATA_EXFIL, norm, subs)) {
            score += W_DATA_EXFIL;
            matchedRules.add("DATA_EXFILTRATION");
            reasons.add("Potential data exfiltration detected");
        }

        // Rule 5 — Download-and-execute
        if (matchesAny(DOWNLOAD_EXEC, norm, subs)) {
            score += W_DOWNLOAD_EXEC;
            matchedRules.add("DOWNLOAD_AND_EXECUTE");
            reasons.add("Download-and-execute pattern detected");
        }

        // Rule 6 — System modification
        if (matchesAny(SYS_MODIFY, norm, subs)) {
            score += W_SYSTEM_MODIFY;
            matchedRules.add("SYSTEM_MODIFICATION");
            reasons.add("System modification detected");
        }

        // Rule 7 — Obfuscation / encoding  (uses ParsedCommand flags)
        if (parsed.isHasBase64Obfuscation() || parsed.isHasHexObfuscation()) {
            score += W_OBFUSCATION;
            matchedRules.add("OBFUSCATION");
            reasons.add("Obfuscation or encoding detected");
        }

        // Rule 8 — Command chaining  (uses ParsedCommand flag)
        if (parsed.isHasChaining()) {
            score += W_CHAINING;
            matchedRules.add("COMMAND_CHAINING");
            reasons.add("Multiple commands chained together");
        }

        // ── 3. Cap score ────────────────────────────────────────
        score = Math.min(score, 100);

        // ── 4. Decision thresholds ──────────────────────────────
        String decision;
        String status;
        if (score <= 29) {
            decision = "ALLOW";
            status   = "AUTO_APPROVED";
        } else if (score <= 69) {
            decision = "NEEDS_APPROVAL";
            status   = "PENDING";
        } else {
            decision = "DENY";
            status   = "BLOCKED";
        }

        String reason = reasons.isEmpty()
                ? "No security risks detected"
                : String.join("; ", reasons);

        // ── 5. Persist audit log ────────────────────────────────
        CommandLog log = new CommandLog();
        log.setRawCommand(parsed.getOriginalCommand());
        log.setNormalizedCommand(norm);
        log.setDecision(decision);
        log.setRiskScore(score);
        log.setMatchedRules(String.join(",", matchedRules));
        log.setReason(reason);
        log.setStatus(status);
        commandLogRepository.save(log);

        // ── 6. Build response ───────────────────────────────────
        CheckResponse resp = new CheckResponse();
        resp.setId(log.getId());
        resp.setRawCommand(parsed.getOriginalCommand());
        resp.setNormalizedCommand(norm);
        resp.setSubCommands(subs);
        resp.setDecision(decision);
        resp.setRiskScore(score);
        resp.setMatchedRules(matchedRules);
        resp.setEvasionFlags(parsed.getDetectedEvasionFlags());
        resp.setReason(reason);
        resp.setStatus(status);

        return resp;
    }

    // ═══════════════════════════════════════════════════════════
    //  HELPER
    // ═══════════════════════════════════════════════════════════

    /**
     * Returns {@code true} if the pattern matches the full
     * normalised command <b>or</b> any individual sub-command.
     */
    private boolean matchesAny(Pattern pattern,
                               String normalizedCommand,
                               List<String> subCommands) {
        if (pattern.matcher(normalizedCommand).find()) {
            return true;
        }
        for (String sub : subCommands) {
            if (pattern.matcher(sub.toLowerCase()).find()) {
                return true;
            }
        }
        return false;
    }
}
