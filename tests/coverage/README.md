# Code Coverage Guide - Sprint 5

This guide outlines the standards, commands, and best practices for measuring and interpreting code coverage in the AI-SecOps Prompt Firewall pipeline.

---

## 1. Purpose of Code Coverage

Code coverage is a metric that measures the percentage of source code executed while running automated test suites. It provides visibility into:
* **Untested Paths**: Identifies conditional branches (e.g., specific error-handling routines or config fallback states) that have not been exercised.
* **Dead Code**: Helps spot unused functions or obsolete statements that can be safely removed.
* **Test Suite Health**: Acts as a quality check on the test suite itself, ensuring broad code validation.

---

## 2. Why Coverage is Vital for AI Security Projects

For security-critical components like `PromptFirewall`, high code coverage is not just a quality metric—it is a security requirement:
* **Evasion Detection**: Validates that obfuscation cleaners (such as Unicode homoglyph normalizers and zero-width spaces scanners) operate correctly across all edge cases without bypassing rules.
* **Resilience Under Load**: Asserts that error boundary wrappers (like `fail_secure` states) successfully isolate crashes and prevent prompt smuggling or service crashes.
* **Determinism**: Ensures logic paths (like matching selection priority rules) always execute exactly as specified under both normal and adversarial inputs.

---

## 3. Recommended Coverage Threshold

For the `security` core subpackage, we establish the following benchmark targets:
* **Minimum Threshold**: **90%** branch coverage.
* **Integration Gate**: Commits falling below **85%** overall coverage will automatically fail the CI/CD pipeline checks.

---

## 4. Commands for Running Coverage

Use the following commands from the root directory to run the test suite with coverage collection.

### Terminal Summary Report
Runs all unit and integration tests under `tests/llm/` and outputs a line-by-line missing statement summary directly to the terminal:
```bash
.venv/bin/pytest tests/llm/ --cov=security --cov-report=term-missing
```
* **Use Case**: Quick developer feedback loop during active refactoring. Shows exactly which lines inside a file were skipped.

### HTML Interactive Report
Generates an interactive, detailed HTML report saved in a local folder named `htmlcov/`:
```bash
.venv/bin/pytest tests/llm/ --cov=security --cov-report=html
```
* **Use Case**: Deep auditing. Visualizes covered lines in green and missed lines in red inside a web browser.

---

## 5. How to Open the HTML Report

Once generated, you can open and inspect the interactive report:

### Linux / Ubuntu
```bash
xdg-open htmlcov/index.html
```

### macOS
```bash
open htmlcov/index.html
```

### Windows (Git Bash / PowerShell)
```bash
start htmlcov/index.html
```

---

## 6. How to Interpret Coverage Metrics

The generated summary table provides three key metrics:

* **Statements**: The total count of executable code instructions (excluding comments, docstrings, and blank lines).
* **Missing**: The count of statement lines that were not executed during the test run.
* **Coverage %**: The percentage of executed statements relative to total statements:
  $$\text{Coverage \%} = \frac{\text{Statements} - \text{Missing}}{\text{Statements}} \times 100$$

---

## 7. Why 100% Coverage is NOT Always Required

Achieving absolute 100% statement coverage can result in diminishing returns:
* **Low-Value Coverage**: Writing complex tests solely to hit trivial statements (e.g., standard debug loggers or simple boilerplate exceptions) takes time away from writing adversarial test cases.
* **Brittle Tests**: Over-mocking external libraries to force execution of obscure OS-level failure conditions can make tests fragile and prone to breaking during dependency updates.
* **False Security**: 100% line coverage does not mean code is free of logic defects or security flaws. Broad boundary condition verification is more valuable than simple line execution.

---

## 8. Realistic Production Targets

We categorize code regions based on their criticality to align testing efforts:

* **80% (Informational / Utility Drivers)**: Standard models, DTOs, and serialization dict helpers.
* **90% (Security Enforcers)**: Text normalizers, regular expression rule compilers, and keyword/phrase matching detectors.
* **95% (Gateway Orchestrator)**: `PromptFirewall` orchestrator core pipeline logic, including `fail_secure` context handling.

---

## 9. Best Practices

1. **Test the Happy Path and the Edge Case**: Ensure both clean prompts and malformed/malicious inputs are validated.
2. **Prioritize Branch Coverage**: Focus on conditional blocks (`if/else` and `try/except`) rather than simple straight-line statements.
3. **Use Mocking Wisely**: Mock external services (like databases and API models) but use concrete instances for local utility libraries (like `TextNormalizer`).
4. **Keep Tests DRY**: Share fixtures and test doubles in a local `conftest.py` file to avoid boilerplate duplication.

---

## 10. Future Recommendations (Sprint 6 and Beyond)

* **Branch Coverage Enforcement**: Transition from line coverage measurement to branch coverage (`--cov-branch`) in Sprint 6.
* **Coverage Trend Badges**: Automatically write and update a coverage percentage badge in the repository `README.md` during CI/CD checks.
* **Fail-Under Rule**: Enforce a strict `--cov-fail-under=90` parameter check inside pre-push Git hooks.
