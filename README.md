# AgentGuard

## Problem Statement

AI agents can generate shell commands that are destructive, privilege-escalating,
obfuscated, or designed to access protected system resources. AgentGuard is a
pre-execution safety gateway that analyzes command text, calculates a risk score,
and requires human approval where appropriate before a command can be considered
safe. It never executes or runs analyzed commands.

## Architecture

```text
React UI -> Spring Boot REST API -> CommandParser -> 8-Rule Scoring Engine -> Audit Log
```

1. The React dashboard sends commands and workflow actions to the Spring Boot REST API.
2. `CommandParser` normalizes the command, splits chained sub-commands, and detects
   obfuscation or traversal patterns.
3. The 8-rule scoring engine adds rule weights and produces an allow, approval, or denial
   decision.
4. The result and approval status are persisted to the audit log.

## 8-Rule Weight Table

| Rule | Risk Weight |
|---|---:|
| 1. Protected path | 40 |
| 2. Destructive command | 55 |
| 3. Privilege escalation | 35 |
| 4. Data exfiltration | 35 |
| 5. Download and execute | 50 |
| 6. System modification | 20 |
| 7. Obfuscation / encoding | 25 |
| 8. Command chaining | 10 |

The final score is capped at 100.

| Risk Score | Decision | Audit Status |
|---|---|---|
| `0–29` | `ALLOW` | `AUTO_APPROVED` |
| `30–69` | `NEEDS_APPROVAL` | `PENDING` |
| `70–100` | `DENY` | `BLOCKED` |

## Run the Backend

From the repository root:

```bash
cd backend
mvn spring-boot:run
```

The backend listens on `http://localhost:8080`. The REST API base URL is
`http://localhost:8080/api`.

## Run the Frontend

From the repository root:

```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0
```

The frontend is available at `http://localhost:5173`.

## Run the Backend Tests

```bash
cd backend
mvn test
```
