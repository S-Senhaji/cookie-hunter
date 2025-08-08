# 🔴 REDHOOD CookieHunter - Security Guide

## 🛡️ Security Features

### Cookie Security Analysis
- **HttpOnly Flag**: Prevents XSS attacks by blocking JavaScript access
- **Secure Flag**: Ensures cookies are only sent over HTTPS
- **SameSite Attribute**: Protects against CSRF attacks
- **Expires/Max-Age**: Controls cookie lifetime
- **Path Attribute**: Restricts cookie scope to specific paths

### Security Warnings
- **Critical**: Missing Secure flag on HTTPS sites
- **Error**: Invalid SameSite values, negative Max-Age
- **Warning**: Missing HttpOnly, long expiration times

## 🔍 Security Checks

### HttpOnly Analysis
```bash
# Good: HttpOnly flag present
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict

# Bad: Missing HttpOnly flag
Set-Cookie: session=abc123; Secure; SameSite=Strict
```

### Secure Flag Analysis
```bash
# Good: Secure flag on HTTPS
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict

# Critical: Missing Secure flag on HTTPS
Set-Cookie: session=abc123; HttpOnly; SameSite=Strict
```

### SameSite Analysis
```bash
# Good: SameSite=Strict (most secure)
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict

# Acceptable: SameSite=Lax
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax

# Risky: SameSite=None (requires Secure flag)
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=None

# Bad: Missing SameSite attribute
Set-Cookie: session=abc123; HttpOnly; Secure
```

## 🚨 Common Security Issues

### 1. Missing HttpOnly Flag
- **Risk**: XSS attacks can steal cookies
- **Solution**: Add `HttpOnly` flag to all session cookies

### 2. Missing Secure Flag on HTTPS
- **Risk**: Cookies sent over HTTP, vulnerable to interception
- **Solution**: Always use `Secure` flag on HTTPS sites

### 3. Missing SameSite Attribute
- **Risk**: CSRF attacks
- **Solution**: Use `SameSite=Strict` for sensitive cookies

### 4. Overly Broad Path
- **Risk**: Cookies sent to unnecessary endpoints
- **Solution**: Restrict path to specific endpoints

### 5. Long Expiration Times
- **Risk**: Prolonged exposure if compromised
- **Solution**: Use shorter expiration times

## 🔧 Remediation Examples

### Before (Insecure)
```bash
Set-Cookie: session=abc123; path=/
```

### After (Secure)
```bash
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; path=/admin; Max-Age=3600
```

## 📊 Security Scoring

| Issue | Severity | Impact |
|-------|----------|--------|
| Missing HttpOnly | Warning | Medium |
| Missing Secure (HTTPS) | Critical | High |
| Missing SameSite | Warning | Medium |
| SameSite=None without Secure | Error | High |
| Long expiration | Warning | Low |
| Broad path | Warning | Low |

## 🎯 Best Practices

1. **Always use HttpOnly** for session cookies
2. **Always use Secure** on HTTPS sites
3. **Use SameSite=Strict** for sensitive cookies
4. **Limit cookie paths** to necessary endpoints
5. **Set reasonable expiration times**
6. **Use __Host- and __Secure- prefixes** appropriately

## 🔗 References

- [OWASP Cookie Security](https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length)
- [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
- [RFC 6265](https://tools.ietf.org/html/rfc6265)

---

**Developer**: @0xRedHood  
**Contact**: amirpedddii@gmail.com  
**Repository**: https://github.com/0xRedHood/CookieHunter 