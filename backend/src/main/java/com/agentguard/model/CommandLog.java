package com.agentguard.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA entity mapped to the {@code command_logs} table.
 * <p>
 * Stores the audit record for every command that AgentGuard analyses.
 * No command is ever executed — only the textual analysis result is persisted.
 */
@Entity
@Table(name = "command_logs")
public class CommandLog {

    // ── primary key ─────────────────────────────────────────────
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // ── command text ────────────────────────────────────────────
    @Column(name = "raw_command", columnDefinition = "TEXT")
    private String rawCommand;

    @Column(name = "normalized_command", columnDefinition = "TEXT")
    private String normalizedCommand;

    // ── verdict ─────────────────────────────────────────────────
    /** ALLOW | NEEDS_APPROVAL | DENY */
    @Column(name = "decision", length = 20)
    private String decision;

    @Column(name = "risk_score")
    private int riskScore;

    /** Comma-separated rule names that matched. */
    @Column(name = "matched_rules", length = 500)
    private String matchedRules;

    @Column(name = "reason", columnDefinition = "TEXT")
    private String reason;

    // ── approval workflow ───────────────────────────────────────
    /** AUTO_APPROVED | PENDING | APPROVED | REJECTED | BLOCKED */
    @Column(name = "status", length = 20)
    private String status;

    // ── timestamp ───────────────────────────────────────────────
    @Column(name = "created_at")
    private LocalDateTime createdAt;

    // ── lifecycle callback ──────────────────────────────────────
    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }

    // ── constructors ────────────────────────────────────────────

    public CommandLog() {
        // JPA requires a no-arg constructor
    }

    // ── getters & setters ───────────────────────────────────────

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getRawCommand() { return rawCommand; }
    public void setRawCommand(String rawCommand) { this.rawCommand = rawCommand; }

    public String getNormalizedCommand() { return normalizedCommand; }
    public void setNormalizedCommand(String normalizedCommand) { this.normalizedCommand = normalizedCommand; }

    public String getDecision() { return decision; }
    public void setDecision(String decision) { this.decision = decision; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public String getMatchedRules() { return matchedRules; }
    public void setMatchedRules(String matchedRules) { this.matchedRules = matchedRules; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}
