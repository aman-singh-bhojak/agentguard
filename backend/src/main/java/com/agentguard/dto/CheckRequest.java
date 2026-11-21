package com.agentguard.dto;

/**
 * Incoming request body for {@code POST /api/check}.
 */
public class CheckRequest {

    private String command;

    // ── constructors ────────────────────────────────────────────

    public CheckRequest() { }

    public CheckRequest(String command) {
        this.command = command;
    }

    // ── getter / setter ─────────────────────────────────────────

    public String getCommand() { return command; }
    public void setCommand(String command) { this.command = command; }
}
