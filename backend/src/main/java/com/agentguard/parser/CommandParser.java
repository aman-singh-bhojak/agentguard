package com.agentguard.parser;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure string-analysis utility for AgentGuard.
 * <p>
 * <b>Contract:</b> This class NEVER executes any command.
 * It only inspects the raw text and returns a {@link ParsedCommand} DTO.
 */
@Component
public class CommandParser {

    // ═══════════════════════════════════════════════════════════
    //  1.  COMPILED REGEX PATTERNS  (created once, reused forever)
    // ═══════════════════════════════════════════════════════════

    // ── Base64 obfuscation ──────────────────────────────────────
    //
    // Pattern A — explicit base64 tool usage:
    //   • "base64 -d", "base64 --decode"
    //   Catches: echo <blob> | base64 -d
    private static final Pattern BASE64_TOOL = Pattern.compile(
            "\\bbase64\\s+(-d|--decode)\\b",
            Pattern.CASE_INSENSITIVE
    );

    // Pattern B — a long Base64 blob piped into something:
    //   • At least 20 chars of [A-Za-z0-9+/=] with optional trailing '='
    //   Catches: echo cm0gLXJmIC8= | …
    private static final Pattern BASE64_BLOB = Pattern.compile(
        "(?<![/\\\\])\\b[A-Za-z0-9+/]{24,}={1,2}|\\b(?=[A-Za-z0-9+/]{20,}\\b)(?=.*[A-Z])(?=.*[a-z])[A-Za-z0-9+/]{20,}\\b"
    );

    // Pattern C — PowerShell encoded-command flag:
    //   • -enc, -EncodedCommand, -encodedcommand (PS accepts prefix)
    private static final Pattern PS_ENCODED = Pattern.compile(
            "-(enc|encodedcommand)\\b",
            Pattern.CASE_INSENSITIVE
    );

    // ── Path traversal ──────────────────────────────────────────
    //
    // Pattern D — literal ../ or ..\ :
    private static final Pattern PATH_TRAV_LITERAL = Pattern.compile(
            "\\.\\.[\\\\/]"
    );

    // Pattern E — URL-encoded traversal (%2e%2e%2f, %2e%2e/ etc.):
    private static final Pattern PATH_TRAV_ENCODED = Pattern.compile(
            "(%2e){2}(%2f|%5c|[\\\\/])",
            Pattern.CASE_INSENSITIVE
    );

    // Pattern F — repeated parent-dir jumps (3+ levels deep):
    //   Catches: ../../../etc/passwd
    private static final Pattern PATH_TRAV_DEEP = Pattern.compile(
            "(\\.\\.([\\\\/])){3,}"
    );

    // ── Hex / octal / char-code evasion ─────────────────────────
    //
    // Pattern G — C-style hex escapes: \x2f, \x72\x6d
    private static final Pattern HEX_ESCAPE = Pattern.compile(
            "\\\\x[0-9a-fA-F]{2}"
    );

    // Pattern H — Bash $'...' quoting with hex/octal inside:
    //   Catches: $'\x72\x6d'  or  $'\162\155'
    private static final Pattern BASH_DOLLAR_QUOTE = Pattern.compile(
            "\\$'[^']*\\\\(x[0-9a-fA-F]{2}|[0-7]{1,3})[^']*'"
    );

    // Pattern I — Unicode escapes often used in PowerShell/Python:
    //   \u002f, \u0072
    private static final Pattern UNICODE_ESCAPE = Pattern.compile(
            "\\\\u[0-9a-fA-F]{4}"
    );

    // Pattern J — Octal escapes outside $'…' (e.g. printf '\162\155'):
    //   Three-digit octal after a backslash
    private static final Pattern OCTAL_ESCAPE = Pattern.compile(
            "\\\\[0-7]{3}"
    );

    // ═══════════════════════════════════════════════════════════
    //  2.  PUBLIC API
    // ═══════════════════════════════════════════════════════════

    /**
     * Parse and analyse a raw command string.
     *
     * @param rawCommand the command exactly as the AI agent sent it
     * @return a fully populated {@link ParsedCommand}; never null
     */
    public ParsedCommand parse(String rawCommand) {
        if (rawCommand == null || rawCommand.isBlank()) {
            return emptyResult(rawCommand == null ? "" : rawCommand);
        }

        // ── step 1: normalise ───────────────────────────────────
        String original   = rawCommand;
        String trimmed    = rawCommand.strip();
        String collapsed  = trimmed.replaceAll("\\s+", " ");  // collapse spaces
        String normalized = collapsed.toLowerCase();            // lowercase copy

        // ── step 2: split chained commands ──────────────────────
        List<String> subCommands = splitChainedCommands(collapsed);
        boolean hasChaining = subCommands.size() > 1;

        // ── step 3: run detectors against the NORMALIZED text ───
        List<String> evasionFlags = new ArrayList<>();

        boolean base64 = detectBase64(collapsed);
        if (base64) evasionFlags.add("BASE64_OBFUSCATION");

        boolean traversal = detectPathTraversal(normalized);
        if (traversal) evasionFlags.add("PATH_TRAVERSAL");

        boolean hex = detectHexObfuscation(collapsed);  // case-sensitive for hex
        if (hex) evasionFlags.add("HEX_OCTAL_CHARCODE_EVASION");

        if (hasChaining) evasionFlags.add("COMMAND_CHAINING");

        return new ParsedCommand(
                original,
                normalized,
                subCommands,
                hasChaining,
                base64,
                traversal,
                hex,
                Collections.unmodifiableList(evasionFlags)
        );
    }

    // ═══════════════════════════════════════════════════════════
    //  3.  CHAINED-COMMAND SPLITTER  (quote-aware)
    // ═══════════════════════════════════════════════════════════

    /**
     * Splits on {@code &&}, {@code ||}, {@code ;}, or single {@code |}
     * while respecting single-quoted and double-quoted regions.
     * <p>
     * The tricky part: we must NOT split on {@code ||} when processing
     * {@code |}, and we must NOT break strings that sit inside quotes.
     */
    private List<String> splitChainedCommands(String command) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();

        boolean inSingle = false;   // inside '…'
        boolean inDouble = false;   // inside "…"
        int i = 0;
        int len = command.length();

        while (i < len) {
            char c = command.charAt(i);

            // ── toggle quote state (skip escaped quotes like \") ──
            boolean isEscaped = isEscaped(command, i);

            if (c == '\'' && !inDouble && !isEscaped) {
                inSingle = !inSingle;
                current.append(c);
                i++;
                continue;
            }
            if (c == '"' && !inSingle && !isEscaped) {
                inDouble = !inDouble;
                current.append(c);
                i++;
                continue;
            }

            // ── only split when outside any quotes ──────────────
            if (!inSingle && !inDouble) {

                // &&
                if (c == '&' && i + 1 < len && command.charAt(i + 1) == '&') {
                    addPart(parts, current);
                    i += 2;
                    continue;
                }
                // ||
                if (c == '|' && i + 1 < len && command.charAt(i + 1) == '|') {
                    addPart(parts, current);
                    i += 2;
                    continue;
                }
                // single |  (not ||)
                if (c == '|') {
                    addPart(parts, current);
                    i++;
                    continue;
                }
                // ;
                if (c == ';') {
                    addPart(parts, current);
                    i++;
                    continue;
                }
            }

            current.append(c);
            i++;
        }

        // whatever remains after the last separator
        addPart(parts, current);
        return parts;
    }

    /** Flush the buffer as one sub-command (trimmed, skip blanks). */
    private void addPart(List<String> parts, StringBuilder buf) {
        String part = buf.toString().strip();
        if (!part.isEmpty()) {
            parts.add(part);
        }
        buf.setLength(0);
    }

    private boolean isEscaped(String text, int index) {
        int slashCount = 0;
        for (int i = index - 1; i >= 0 && text.charAt(i) == '\\'; i--) {
            slashCount++;
        }
        return slashCount % 2 == 1;
    }

    // ═══════════════════════════════════════════════════════════
    //  4.  DETECTOR METHODS
    // ═══════════════════════════════════════════════════════════

    private boolean detectBase64(String text) {
        return BASE64_TOOL.matcher(text).find()
                || PS_ENCODED.matcher(text).find()
                || BASE64_BLOB.matcher(text).find();
    }

    private boolean detectPathTraversal(String text) {
        return PATH_TRAV_LITERAL.matcher(text).find()
                || PATH_TRAV_ENCODED.matcher(text).find()
                || PATH_TRAV_DEEP.matcher(text).find();
    }

    private boolean detectHexObfuscation(String text) {
        return HEX_ESCAPE.matcher(text).find()
                || BASH_DOLLAR_QUOTE.matcher(text).find()
                || UNICODE_ESCAPE.matcher(text).find()
                || OCTAL_ESCAPE.matcher(text).find();
    }

    // ═══════════════════════════════════════════════════════════
    //  5.  HELPER
    // ═══════════════════════════════════════════════════════════

    private ParsedCommand emptyResult(String original) {
        return new ParsedCommand(
                original, "", List.of(), false, false, false, false, List.of()
        );
    }
}
