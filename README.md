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

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## ⚠️ Legal Disclaimer

### Educational Purpose Only
This tool is provided strictly for **educational purposes** and **authorized security testing** only. It is intended to help security professionals and students learn about security concepts in controlled environments.

### Authorized Use Only
- You must have **explicit written authorization** before testing any system you do not own
- Unauthorized access to computer systems is **illegal** and punishable under laws including but not limited to the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, and similar legislation worldwide
- Only use this tool on systems you own, have permission to test, or in isolated lab environments

### No Warranty
This software is provided "AS IS" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. The author makes no representations or warranties regarding the accuracy, completeness, or reliability of this software.

### Limitation of Liability
**In no event shall the author (Nikhil Nagpure) be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.**

### User Responsibility
- The user assumes **full responsibility** for any consequences resulting from the use of this tool
- The author is **not responsible** for any misuse, damage, or illegal activities performed with this software
- Users are solely responsible for ensuring compliance with all applicable local, state, national, and international laws and regulations

### Indemnification
By using this software, you agree to **indemnify, defend, and hold harmless** the author from and against any and all claims, liabilities, damages, losses, costs, and expenses (including reasonable attorneys fees) arising from or related to your use of this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, please follow responsible disclosure practices and report them to the affected parties through appropriate channels.

---

**By using this software, you acknowledge that you have read, understood, and agree to be bound by this disclaimer.**
## License

This project is for educational purposes only. Use responsibly and ethically.

---

**Remember**: Always get explicit authorization before checking any website!
