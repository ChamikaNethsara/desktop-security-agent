# Security Agent

Real-time secret scanner and static configuration risk auditor.

## Setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Run

From the `security_agent` directory:

```bash
python -m app.main ./test_configs
```

Stop monitoring with Ctrl+C. The secret scanner persists findings in `data/security_agent.db`; configuration auditing runs on each eligible file and logs findings.

## Tests

```bash
python -m pytest -q
```

## Modules

- `app/`: main entry point and integration
- `scanner/`: secret detection and file monitoring
- `auditor/`: configuration parser, rule engine, findings, risk scoring
- `config/auditor_rules/`: CFG-001 through CFG-010
- `storage/`: event storage
- `tests/`: unit tests
