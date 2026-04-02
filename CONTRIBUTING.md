# Contributing to Recon-Scan

First, thanks for considering contributing to Recon-Scan.

This project is designed to stay lightweight, privacy-focused, and genuinely useful for passive security posture assessment. Contributions should preserve those priorities:
- passive recon only
- developer-first workflows
- self-host friendly architecture
- clean reporting and explainability
- safe defaults

Please read this document before opening a pull request.

---

## Project Philosophy

Recon-Scan is intentionally focused.

### What belongs here
Good contributions include:
- improvements to passive recon modules
- performance optimizations
- frontend UX improvements
- PDF/reporting enhancements
- worker reliability improvements
- test coverage
- deployment/dev workflow improvements
- documentation fixes
- AI summary quality improvements
- better false-positive reduction logic

### What does not belong here
Please avoid PRs that add:
- active exploitation
- brute force logic
- fuzzing engines
- intrusive scanners
- denial-of-service style probing
- malware-like persistence or stealth behavior

The point is fast, safe signal, not offensive tooling.

---

## Development Setup

### Quick local start

    ./start.sh

### Docker setup

    ./start-docker.sh

### Manual setup

    pip install -r requirements.txt
    cp .env.example .env
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

Recommended second terminal:

    arq app.worker.WorkerSettings

---

## Branch Naming

Use clear branch names:

- `feat/module-csp-analysis`
- `fix/pdf-render-timeout`
- `docs/api-clarifications`
- `test/scan-pipeline-regression`
- `refactor/worker-retry-flow`

Avoid vague branch names like `update-stuff`.

---

## Coding Standards

### Python
- Follow PEP 8
- Prefer typed functions
- Keep functions small and composable
- Use descriptive names
- Favor async-safe patterns where relevant
- Fail safely and log meaningful errors

### Frontend
- Keep UI responsive and minimal
- Preserve single-page simplicity
- Prefer readable vanilla JS/HTML patterns already used in the repo
- Avoid unnecessary framework bloat unless there is a strong architectural reason

### Security modules
When adding or editing scan modules:
- preserve passive-only behavior
- avoid noisy requests
- prevent duplicate findings
- normalize severity output
- return structured machine-readable results
- ensure modules degrade gracefully on timeout/failure

---

## Testing

Install dev dependencies:

    pip install -r requirements-dev.txt

Run tests:

    pytest -q

### For new features
If your PR adds:
- a new module
- API behavior
- worker logic
- PDF formatting
- severity scoring
- target validation

include tests.

At minimum, cover:
- expected success path
- malformed input
- timeout/error fallback
- regression edge case

---

## Pull Request Guidelines

Before opening a PR, make sure:
- code is tested
- existing tests still pass
- docs are updated if behavior changed
- no secrets/API keys are committed
- `.env.example` is updated if config changes
- feature scope is focused

### PR description template

    ## Summary
    What changed?

    ## Why
    Why is this useful?

    ## Testing
    How was this verified?

    ## Screenshots / Output
    If UI or PDF related

Small, focused PRs are easier to review.

---

## Module Contribution Rules

For passive scan modules, follow this output structure consistently:

    {
        "module": "security_headers",
        "severity": "medium",
        "summary": "Missing HSTS header",
        "details": {}
    }

Use:
- predictable keys
- normalized severity labels
- deterministic output
- no provider-specific weirdness

Consistency matters because reports, AI summaries, and PDF exports depend on stable schema.

---

## Reporting Bugs

When opening an issue, include:
- target input used
- expected result
- actual result
- logs/errors
- environment (local/docker)
- screenshots if frontend related
- steps to reproduce

---

## Feature Requests

Feature requests are welcome if they improve:
- passive signal quality
- speed
- reporting clarity
- privacy
- self-hosting
- educational usefulness for defenders

Requests for offensive security behavior will be closed.

---

## Code of Conduct

Be respectful, precise, and technical.

Disagreements about implementation are normal.
Argue from:
- evidence
- benchmarks
- RFCs
- reproducible behavior
- security reasoning

---

## First Contribution Ideas

Good starter contributions:
- improve false-positive reduction
- better PDF layout formatting
- frontend loading states
- retry logic for flaky passive modules
- better DNS parsing edge cases
- improve tests for private target blocking
- docs/examples for self-host deployment

---

## Final Note

Recon-Scan succeeds by staying focused:
**fast passive recon + clean reporting + safe defaults**

If your contribution strengthens that triangle, it belongs here.
