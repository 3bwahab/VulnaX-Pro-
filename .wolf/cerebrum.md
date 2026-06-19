# Cerebrum — VulnaX-Pro

Learnings, preferences, and a Do-Not-Repeat list. Consult before generating code.

## Preferences
- User wants a commercial-grade, production-quality framework — favor depth,
  professional structure, and explainability over quick hacks.
- UX rule: never expose raw tool output ("Running subfinder...") to the user;
  always show curated enterprise dashboard counters.

## Learnings
- Project started as an empty directory on 2026-06-15; design-first approach
  requested (produce 16 deliverables before any code).
- Platform: Windows 11, PowerShell primary shell; project not a git repo.
- Design delivered as docs/00..12 markdown files (consolidated 16 deliverables).

## Do-Not-Repeat (code-gen guardrails)
- Do NOT make engines import each other — communicate via the store + typed models.
- Do NOT call subprocesses from engines — only via the integration/adapter layer.
- Do NOT generate payloads/exploits — Payload Intelligence only SELECTS existing
  resources.
- Do NOT create a Finding without non-empty Evidence (schema rejects it).
- Do NOT introduce SaaS/web/microservice/DB-server/Docker/k8s dependencies — single
  local process only.
- Do NOT bypass the scope guard; enforce at integration layer.
