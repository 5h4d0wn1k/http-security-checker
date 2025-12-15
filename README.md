# HTTP Security Header Checker

⚠️ **EDUCATIONAL PURPOSE ONLY** - This tool is designed for authorized security testing and educational purposes. Only use on websites you own or have explicit written authorization to test.

## Overview

A comprehensive HTTP security header analyzer that checks for common security headers and misconfigurations. Helps identify missing security headers and provides recommendations for improvement.

## Features

- **Security Header Detection**: Checks for common security headers
- **TLS Analysis**: Analyzes TLS/SSL configuration
- **Misconfiguration Detection**: Identifies security misconfigurations
- **JSON Reporting**: Machine-readable output for automation
- **Easy to Use**: Simple command-line interface

## Security Headers Checked

- **Strict-Transport-Security (HSTS)**: Enforces HTTPS connections
- **Content-Security-Policy (CSP)**: Prevents XSS attacks
- **X-Frame-Options**: Prevents clickjacking
- **X-Content-Type-Options**: Prevents MIME sniffing
- **Referrer-Policy**: Controls referrer information
- **Permissions-Policy**: Controls browser features

## Installation

### Requirements

- Python 3.8+
- Standard library only (no external dependencies!)

### Setup

```bash
# Clone the repository
git clone https://github.com/5h4d0wn1k/http-security-checker.git
cd http-security-checker

# No installation needed!
python http_security_check.py --help
```

## Usage

### Basic Usage

```bash
# Check security headers
python http_security_check.py --url https://example.com
```

### Save Results

```bash
# Save results to JSON file
python http_security_check.py \
  --url https://example.com \
  --json-out security_report.json
```

### Custom Timeout

```bash
# Set custom timeout
python http_security_check.py \
  --url https://example.com \
  --timeout 10.0
```

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--url` | Target URL to check (required) | - |
| `--timeout` | Request timeout (seconds) | 5.0 |
| `--json-out` | Save results to JSON file | stdout |

## Output Format

### Console Output

```
⚠️  Authorized use only. Test only sites you own/control.
{
  "url": "https://example.com",
  "status": 200,
  "headers": {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    ...
  },
  "findings": {
    "strict-transport-security": "present",
    "content-security-policy": "present",
    "x-frame-options": "missing",
    ...
  }
}
```

### JSON Output

```json
{
  "url": "https://example.com",
  "status": 200,
  "headers": {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=(), microphone=()"
  },
  "findings": {
    "strict-transport-security": "present",
    "content-security-policy": "present",
    "x-frame-options": "present",
    "x-content-type-options": "present",
    "referrer-policy": "present",
    "permissions-policy": "present"
  }
}
```

## Examples

### Example 1: Basic Security Check

```bash
# Check your website's security headers
python http_security_check.py \
  --url https://yourwebsite.com \
  --json-out security_check.json
```

### Example 2: Batch Checking

```bash
# Check multiple URLs
for url in https://site1.com https://site2.com https://site3.com; do
  python http_security_check.py --url "$url" --json-out "${url##*/}_security.json"
done
```

## Interpreting Results

### Missing Headers

If a header is marked as "missing", it means the server is not sending that security header. Consider adding it to improve security.

### Present Headers

Headers marked as "present" are being sent by the server. Review their values to ensure they're configured correctly.

## Recommendations

### HSTS

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### CSP

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
```

### X-Frame-Options

```http
X-Frame-Options: DENY
```

### X-Content-Type-Options

```http
X-Content-Type-Options: nosniff
```

## Use Cases

- **Security Audits**: Check security headers on your websites
- **Compliance**: Ensure security headers meet compliance requirements
- **Penetration Testing**: Authorized security assessments
- **Educational Purposes**: Learn about HTTP security headers

## Legal Disclaimer

⚠️ **IMPORTANT**: This tool is for authorized security testing and educational purposes only.

- Only check websites you own or have explicit written authorization to test
- Respect rate limits and don't overload target servers
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is for educational purposes only. Use responsibly and ethically.

---

**Remember**: Always get explicit authorization before checking any website!
