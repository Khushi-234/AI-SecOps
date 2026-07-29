# AI-SecOps Project Architecture

This document describes the high-level architecture, design decisions, and data flow of the AI-SecOps security assessment framework.

---

## 🏗️ System Overview

The framework is structured as a decoupled scanning, testing, and mitigation pipeline that evaluates a **Target LLM Application** against adversarial security prompts.

```
       ┌────────────────────────┐
       │     Security Audit     │
       │    (generator.py)      │
       └───────────┬────────────┘
                   │
         [Adversarial Payload]
                   │
                   ▼
       ┌────────────────────────┐
       │   Target Application   │
       │       (app.py)         │
       └───────────┬────────────┘
                   │
           [LLM Response]
                   │
                   ▼
       ┌────────────────────────┐
       │ Vulnerability Judge    │
       │     (evaluator.py)     │
       └───────────┬────────────┘
                   │
           [Security Verdict]
                   │
                   ▼
       ┌────────────────────────┐
       │  Database & Reporting  │
       │  (report.py/SQLite)    │
       └────────────────────────┘
```

---

## 🧩 Architectural Components

### 1. The Audit Orchestrator (`scanner/`)
* **[generator.py](file:///home/bisag/Downloads/M.Tech_Project_Juhi/Project_AISecOps/ai-secops-framework/scanner/generator.py)**: Acts as the primary orchestrator. It manages the attack lifecycle:
  1. Retrieves the set of simulated adversarial prompts (11 unique categories, e.g., jailbreaks, smuggling, evasion).
  2. Executes comparative testing (Phase 1: Undefended model vs. Phase 2: Guarded/hardened model).
  3. Feeds responses to the evaluator, computes cumulative risk indices, and hands off outputs for database persistence.
* **[evaluator.py](file:///home/bisag/Downloads/M.Tech_Project_Juhi/Project_AISecOps/ai-secops-framework/scanner/evaluator.py)**: Performs the assessment using the class `VulnerabilityEvaluator`. It uses a cloud-based Llama-3 model as a judge to assess if the model has successfully refused an exploit (`Safe Refusal`), leaked a system secret, or failed containment (`Vulnerability Confirmed`).
* **[report.py](file:///home/bisag/Downloads/M.Tech_Project_Juhi/Project_AISecOps/ai-secops-framework/scanner/report.py)**: Manages database transaction handling for sqlite and builds standalone Markdown report assets under `/reports/`.

### 2. The Target System Under Test (`target_app/`)
* **[app.py](file:///home/bisag/Downloads/M.Tech_Project_Juhi/Project_AISecOps/ai-secops-framework/target_app/app.py)**: Represents the application under evaluation.
  * **Undefended Route (`query`)**: Forwards raw inputs to the LLM backend with the default system instructions.
  * **Defended Route (`secure_query`)**: Wraps inputs inside unique, dynamically-generated XML tags (`<user_query_xxxxxx>`) to contain execution. It also parses outputs to scrub matching patterns (like secret keys `CX-\d{4}-SECURE` and system compromise indicators).

### 3. Configuration & Declarative Policies (`config/`)
* **[settings.py](file:///home/bisag/Downloads/M.Tech_Project_Juhi/Project_AISecOps/ai-secops-framework/config/settings.py)**: Handles runtime variables loaded from `.env` using Pydantic Settings.
* **[security_policy.yaml](file:///home/bisag/Downloads/M.Tech_Project_Juhi/Project_AISecOps/ai-secops-framework/config/security_policy.yaml)**: Declarative file defining enabled protection components (e.g. firewall filters, logging options, output checkers, PII detectors).
* **[prompts.yaml](file:///home/bisag/Downloads/M.Tech_Project_Juhi/Project_AISecOps/ai-secops-framework/config/prompts.yaml)**: Centralizes standard prompt templates for developer, system, and security contexts.

---

## 🔄 Core Audit Data Flow

The lifecycle of a single audit scan executes as follows:

1. **Initialization**: The audit runner instantiates the target application and loading configuration states.
2. **Exploitation Phase**:
   * For each attack payload, `generator.py` calls the target application’s API.
   * In Phase 1, the target app evaluates the query using default settings.
   * In Phase 2, the target app applies input sanitization, dynamic tag containment, and output semantic validation.
3. **Evaluation Phase**:
   * If the target app’s guardrail intercepted the exploit locally (indicated by `"Refusal:"` or `"[REDACTED]"`), the scanner skips remote LLM judging and registers it as mitigated (Risk: 1.5).
   * Otherwise, the raw response text is dispatched to `evaluator.py`, where Llama-3-Judge runs a classification template to score the risk (0.0 for Safe Refusal, 8.5 for Vulnerability Confirmed).
4. **Persistence & Reporting**:
   * Logs are inserted into SQLite (`scans` and `scan_results` tables).
   * A Markdown report detailing the findings is saved to the `/reports/` folder.
