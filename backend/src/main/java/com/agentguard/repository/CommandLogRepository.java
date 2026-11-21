package com.agentguard.repository;

import com.agentguard.model.CommandLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Spring Data JPA repository for {@link CommandLog} entities.
 * <p>
 * Query methods follow the Spring Data naming convention so
 * implementations are auto-generated at runtime.
 */
@Repository
public interface CommandLogRepository extends JpaRepository<CommandLog, Long> {

    /** All logs, newest first. */
    List<CommandLog> findAllByOrderByCreatedAtDesc();

    /** Logs filtered by decision (ALLOW / NEEDS_APPROVAL / DENY), newest first. */
    List<CommandLog> findByDecisionOrderByCreatedAtDesc(String decision);

    /** Count of logs with a given decision — used by the stats endpoint. */
    long countByDecision(String decision);
}
