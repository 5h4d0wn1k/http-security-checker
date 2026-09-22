> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# HTTP Security Checker

An **HTTP security header analyzer** that scans websites for hardening gaps —
**HSTS, CSP, clickjacking, MIME-sniffing**, and privacy headers — for
**authorized security testing** and education.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/http-security-checker)](https://github.com/5h4d0wn1k/http-security-checker)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/http-security-checker)](https://github.com/5h4d0wn1k/http-security-checker)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/http-security-checker)](https://github.com/5h4d0wn1k/http-security-checker)

## Why HTTP Security Checker

Most breaches start with a website that sends the wrong headers: no
Strict-Transport-Security leaves users open to downgrade attacks, a missing
Content-Security-Policy enables XSS, and absent X-Frame-Options allows
clickjacking. This lightweight scanner fetches one URL, reads every security
header, and reports present/missing findings with clear remediation guidance.
Use it only on sites **you own or have explicit written authorization to test**
— and keep your favorite websites out of its scope.

## Features

- **Security header detection** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **TLS/response analysis** — status code and header transparency on every check
- **Misconfiguration guidance** — recommends the correct header value for each finding
- **JSON reporting** — `--json-out` saves machine-readable results for automation
- **Configurable timeout** — `--timeout` for slow or remote endpoints
- **Zero dependencies** — Python 3.8+ standard library only

## Quickstart

```bash
# Interactive check
python http_security_check.py --url https://example.com

# Save a JSON report
python http_security_check.py --url https://example.com --json-out report.json

# Longer timeout for slow services
python http_security_check.py --url https://example.com --timeout 10.0

# Batch check your own sites
for url in https://site1.com https://site2.com; do
  python http_security_check.py --url "$url" --json-out "${url#https://}.json"
done
```

## Project structure

- `http_security_check.py` — fetch, analyze, and report logic
- `requirements.txt`, `CHANGELOG.md`, `VERSION` — packaging metadata
- `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `ETHICS.md`, `SCOPE.md`, `SECURITY.md` — standards and legal scope

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).

## Legal

- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md) · [SECURITY.md](SECURITY.md)