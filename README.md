# 🔴 REDHOOD CookieHunter

Advanced HTTP Cookie Security Analysis Tool

**Developer:** [@0xRedHood](https://github.com/0xRedHood)  
**Contact:** amirpedddii@gmail.com  
**Repository:** https://github.com/0xRedHood/CookieHunter

## 🎯 Overview

REDHOOD CookieHunter is a comprehensive security analysis tool designed to identify and report potential vulnerabilities in HTTP cookie configurations. It provides detailed analysis of cookie security attributes including HttpOnly, Secure, SameSite, and more.

## 🚀 Quick Start

## 📦 Installation

```bash
git clone https://github.com/0xRedHood/CookieHunter.git
cd CookieHunter
pip install -r requirements.txt
```

## 🛠️ Usage

### Basic Analysis
```bash
python cookie_hunter.py https://example.com
```

### POST Request with Data
```bash
python cookie_hunter.py https://example.com --method POST --data '{"key": "value"}'
```

### With Custom Headers
```bash
python cookie_hunter.py https://example.com --header "User-Agent: CookieHunter/1.0"
```

### Save Results to File
```bash
python cookie_hunter.py https://example.com --output results.txt
```

### Save Results as JSON
```bash
python cookie_hunter.py https://example.com --output results.json --json
```

### 🌐 Web Interface
```bash
python web_interface.py
# Then open http://localhost:5000 in your browser
```

## ✨ Features

- ✅ HttpOnly flag checking
- ✅ Secure flag checking  
- ✅ SameSite attribute checking
- ✅ Expires/Max-Age analysis
- ✅ Path attribute analysis
- ✅ Colored output display
- ✅ Custom headers support
- ✅ POST request support with JSON data
- ✅ Response.cookies analysis (in addition to Set-Cookie headers)
- ✅ Save results to file (text or JSON format)
- ✅ Security warning messages with severity levels
- ✅ Critical warnings for missing Secure flag on HTTPS
- ✅ Remediation guidance for each security issue
- ✅ Web interface for easy analysis
- ✅ Comprehensive security documentation
- ✅ Interactive web interface with detailed warnings
- ✅ Modal popup for detailed cookie analysis
- ✅ Security scoring and remediation guidance

## 📊 Example Output

```
Cookie Security Analysis Results
┌─────────┬──────────────┬──────────┬────────┬──────────┬─────────────────────┐
│ Cookie  │ Value        │ HttpOnly │ Secure │ SameSite │ Warnings            │
│ Name    │              │          │        │          │                     │
├─────────┼──────────────┼──────────┼────────┼──────────┼─────────────────────┤
│ session │ abc123...    │ ✅       │ ❌     │ Strict   │ ⚠️ 3 Issues         │
└─────────┴──────────────┴──────────┴────────┴──────────┴─────────────────────┘
```

## 🔍 Security Analysis

### Cookie Security Checks
- **HttpOnly Flag**: Prevents XSS attacks by blocking JavaScript access
- **Secure Flag**: Ensures cookies are only sent over HTTPS
- **SameSite Attribute**: Protects against CSRF attacks
- **Expires/Max-Age**: Controls cookie lifetime
- **Path Attribute**: Restricts cookie scope to specific paths

### Security Warnings
- **🔥 Critical**: Missing Secure flag on HTTPS sites
- **❌ Error**: Invalid SameSite values, negative Max-Age
- **⚠️ Warning**: Missing HttpOnly, long expiration times

## 📚 Documentation

- **[Security Guide](SECURITY_GUIDE.md)** - Comprehensive security documentation
- **[License](LICENSE)** - MIT License

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Made with by [@0xRedHood](https://github.com/0xRedHood)** 