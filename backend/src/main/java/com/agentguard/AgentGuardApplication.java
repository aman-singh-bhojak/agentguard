package com.agentguard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the AgentGuard backend.
 * <p>
 * AgentGuard is a decision layer that analyses AI-agent commands and
 * returns a verdict (ALLOW / NEEDS_APPROVAL / DENY).
 * It <b>never</b> executes any command.
 */
@SpringBootApplication
public class AgentGuardApplication {

    public static void main(String[] args) {
        SpringApplication.run(AgentGuardApplication.class, args);
    }
}
