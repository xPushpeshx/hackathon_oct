# SAST/DAST Correlation Engine MVP

This repository follows the implementation plan in [plan.md](./plan.md). The Flask-first foundation is now in place and the missing `flask-demo` target has been restored so the engine can discover the seeded routes and validate the static-analysis contracts.

## Current status

| Area | Status |
|---|---|
| Flask target profile and runtime metadata | Implemented |
| Flask demo app with seeded route patterns and vulnerabilities | Implemented under `targets/flask-demo` |
| Flask AST route discovery and conversion to engine route models | Implemented; unit tested |
| Express/JavaScript target scaffold and route discovery | Implemented in `engine/ast_express.py` and `targets/juice-shop` |
| Semgrep result parsing and source-scope route mapping | Implemented; unit tested with mocked Semgrep output |
| Real Semgrep execution | Not verified unless the `semgrep` executable is installed on `PATH` |
| TypeScript bridge dependency for the JS/TS parser | Added via `package.json` and `npm install` |
| ZAP route/task planning and queue generation | Implemented in `engine/zap_runner.py`; execution requires a running OWASP ZAP instance |
| Correlation rules and JSON/HTML report generation | Implemented in `engine/correlate.py` and `engine/report.py` |
| GraphCodeBERT scoring fallback and planner priority logic | Implemented in `engine/gcb.py` and `engine/planner.py` |
| Juice Shop evaluation pipeline | Still intentionally deferred until the parser/runtime ecosystem is validated end-to-end |

The CLI writes a JSON snapshot to `reports/<target>/report.json`. When Semgrep is unavailable, the report records `semgrep.status: "failed"` and does not present that stage as clean.

## Versions and pinning

The Python dependencies in `pyproject.toml` are minimum-version ranges, not exact pins. The local validation environment used Python 3.14, Flask 3.1.3, Pydantic 2.14.2, PyYAML 6.0.3, and pytest 9.2.0. Scan-version metadata is recorded in `config/scan_profile.yaml` and copied into each JSON scan record.

| Component | Current record |
|---|---|
| Python | Project requirement: 3.11+ |
| Flask demo target | `targets/flask-demo` with Dockerfile and runtime config |
| Flask package | Local validation: 3.1.3; container target: 3.0.3 |
| Semgrep | `1.82.0` ([upstream release](https://github.com/semgrep/semgrep/releases/tag/v1.82.0)); install separately and ensure `semgrep` is on `PATH` |
| OWASP ZAP | `ghcr.io/zaproxy/zaproxy:2.16.0` ([upstream release](https://github.com/zaproxy/zaproxy/releases/tag/v2.16.0)); not yet configured or run |
| Juice Shop | `v20.3.0` ([upstream release](https://github.com/juice-shop/juice-shop/releases/tag/v20.3.0)); target implementation remains deferred |
| GraphCodeBERT | `microsoft/graphcodebert-base` at immutable revision `2b0488a7bb0eefc7041f1bb2cad1ab26b0da269d` ([model revision](https://huggingface.co/microsoft/graphcodebert-base/tree/2b0488a7bb0eefc7041f1bb2cad1ab26b0da269d)) |

## Local setup

Use Python 3.11 or newer. From PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
npm install
```

The JavaScript parser depends on the TypeScript compiler API, so the Node dependencies must be installed before the Express target is parsed. The repo now includes a lightweight `package.json` for that dependency.

The scan runs inside an isolated Docker network shared only by the Flask demo, ZAP, and engine. The target and ZAP API are not published to host ports. Copy `.env.example` to `.env`, then run:

```powershell
docker compose run --rm engine
docker compose down
```

The engine image installs the pinned Semgrep version and project dependencies at startup. Reports are written to the host-mounted `reports/` directory. The intentionally vulnerable Flask target is reachable only from services on its Docker network.

The CLI uses Semgrep `1.82.0` from `PATH` when available. Otherwise, when Docker is available, it runs the pinned `semgrep/semgrep:1.82.0` image with the repository mounted read-only and container networking disabled. If neither runner is available, the scan records SAST as failed.

Before scanning, the CLI verifies the Flask target identity by requesting `/search` with a harmless probe value and checking the JSON response. A merely reachable unrelated service is rejected. ZAP's API is authenticated and is not published outside the isolated Docker network.

Run the unit tests with:

```powershell
python -m pytest -q
```

## Commands

```powershell
python -m engine.cli scan --target flask-demo --profile config/scan_profile.yaml
```

`eval` is not implemented yet and exits with a non-zero status. Juice Shop is not currently a supported scan target.
