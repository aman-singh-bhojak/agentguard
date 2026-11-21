package com.agentguard.dto;

import java.util.List;

/**
 * Response body returned by {@code POST /api/check} and
 * {@code POST /api/demo/simulate}.
 */
public class CheckResponse {

    private Long   id;
    private String rawCommand;
    private String normalizedCommand;
    private List<String> subCommands;
    private String decision;
    private int    riskScore;
    private List<String> matchedRules;
    private List<String> evasionFlags;
    private String reason;
    private String status;

    // ── constructors ────────────────────────────────────────────

    public CheckResponse() { }

    // ── getters & setters ───────────────────────────────────────

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getRawCommand() { return rawCommand; }
    public void setRawCommand(String rawCommand) { this.rawCommand = rawCommand; }

    public String getNormalizedCommand() { return normalizedCommand; }
    public void setNormalizedCommand(String normalizedCommand) { this.normalizedCommand = normalizedCommand; }

    public List<String> getSubCommands() { return subCommands; }
    public void setSubCommands(List<String> subCommands) { this.subCommands = subCommands; }

    public String getDecision() { return decision; }
    public void setDecision(String decision) { this.decision = decision; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public List<String> getMatchedRules() { return matchedRules; }
    public void setMatchedRules(List<String> matchedRules) { this.matchedRules = matchedRules; }

    public List<String> getEvasionFlags() { return evasionFlags; }
    public void setEvasionFlags(List<String> evasionFlags) { this.evasionFlags = evasionFlags; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
}
