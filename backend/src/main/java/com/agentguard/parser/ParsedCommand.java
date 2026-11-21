package com.agentguard.parser;

import java.util.List;

/**
 * DTO returned by {@link CommandParser#parse(String)}.
 * <p>
 * Holds every piece of information the Rule Engine and Audit Log
 * need downstream — the original text, the normalised form, the
 * sub-commands found after splitting on chain operators, and all
 * obfuscation / attack flags.
 * <p>
 * This class is intentionally an immutable record-style POJO
 * (Java 17 records could also be used; a class is shown here for
 * maximum Spring / Jackson compatibility).
 */
public class ParsedCommand {

    // ── preserved exactly as the agent sent it ──────────────────
    private final String originalCommand;

    // ── trimmed, single-spaced, lowercased ──────────────────────
    private final String normalizedCommand;

    // ── individual commands after splitting on &&, ||, ;, | ─────
    private final List<String> subCommands;

    // ── flags ───────────────────────────────────────────────────
    private final boolean hasChaining;
    private final boolean hasBase64Obfuscation;
    private final boolean hasPathTraversal;
    private final boolean hasHexObfuscation;

    // ── human-readable list of every evasion technique found ────
    private final List<String> detectedEvasionFlags;

    // ── constructor ─────────────────────────────────────────────
    public ParsedCommand(String originalCommand,
                         String normalizedCommand,
                         List<String> subCommands,
                         boolean hasChaining,
                         boolean hasBase64Obfuscation,
                         boolean hasPathTraversal,
                         boolean hasHexObfuscation,
                         List<String> detectedEvasionFlags) {
        this.originalCommand      = originalCommand;
        this.normalizedCommand    = normalizedCommand;
        this.subCommands          = List.copyOf(subCommands);      // immutable
        this.hasChaining          = hasChaining;
        this.hasBase64Obfuscation = hasBase64Obfuscation;
        this.hasPathTraversal     = hasPathTraversal;
        this.hasHexObfuscation    = hasHexObfuscation;
        this.detectedEvasionFlags = List.copyOf(detectedEvasionFlags);
    }

    // ── getters ─────────────────────────────────────────────────

    public String getOriginalCommand()         { return originalCommand; }
    public String getNormalizedCommand()        { return normalizedCommand; }
    public List<String> getSubCommands()        { return subCommands; }
    public boolean isHasChaining()              { return hasChaining; }
    public boolean isHasBase64Obfuscation()     { return hasBase64Obfuscation; }
    public boolean isHasPathTraversal()         { return hasPathTraversal; }
    public boolean isHasHexObfuscation()        { return hasHexObfuscation; }
    public List<String> getDetectedEvasionFlags() { return detectedEvasionFlags; }

    // ── toString (handy for logging and JUnit assertions) ───────
    @Override
    public String toString() {
        return "ParsedCommand{" +
                "original='" + originalCommand + '\'' +
                ", normalized='" + normalizedCommand + '\'' +
                ", subCommands=" + subCommands +
                ", chaining=" + hasChaining +
                ", base64=" + hasBase64Obfuscation +
                ", pathTraversal=" + hasPathTraversal +
                ", hex=" + hasHexObfuscation +
                ", evasionFlags=" + detectedEvasionFlags +
                '}';
    }
}
