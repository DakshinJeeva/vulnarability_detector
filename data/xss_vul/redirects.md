VULNERABILITY: XSS
PATTERN: Reflected XSS via redirects
CWE: CWE-79
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
Redirect URL parameters (req.query.redirect, req.query.next, req.query.return)

SINK:
Redirect confirmation pages or JavaScript-based redirects displaying URL

DESCRIPTION:
Reflected XSS via redirects occurs when redirect URLs are displayed to
users before redirection or used in JavaScript redirect logic without
sanitization. Attackers inject scripts into redirect parameters that
execute on confirmation pages or in client-side redirect code.

WHY_THIS_IS_DANGEROUS:
- Common in login flows (redirect after login)
- Users expect redirects, lower suspicion
- JavaScript redirects especially vulnerable
- Can be combined with open redirect attacks
- Bypasses server-side URL validation

DETECTION_RULE:
Flag when:
- Redirect URLs displayed in confirmation pages
- JavaScript uses unsanitized redirect parameter
- window.location set from user input
- Meta refresh tags include user-controlled URLs

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Redirect URLs validated against allowlist
- Server-side redirects only (no user display)
- URLs encoded before JavaScript use
- Relative paths enforced

EXAMPLE_VULNERABLE_CODE:
```js
app.get('/login', (req, res) => {
  const redirectUrl = req.query.redirect || '/dashboard';
  
  res.send(`
    <h1>Login</h1>
    <p>You will be redirected to: ${redirectUrl}</p>
    <script>
      setTimeout(() => {
        window.location = "${redirectUrl}";
      }, 2000);
    </script>
  `);
});

app.get('/external', (req, res) => {
  const url = req.query.url;
  res.send(`
    <p>Redirecting to ${url}...</p>
    <meta http-equiv="refresh" content="0;url=${url}">
  `);
});
```

EXAMPLE_SAFE_CODE:
```js
const escapeHtml = require('escape-html');
const url = require('url');

app.get('/login', (req, res) => {
  const redirectUrl = req.query.redirect || '/dashboard';
  
  // Validate redirect URL
  const allowedPaths = ['/dashboard', '/profile', '/settings'];
  if (!allowedPaths.includes(redirectUrl)) {
    return res.status(400).send('Invalid redirect URL');
  }
  
  // Server-side redirect (safe)
  res.redirect(redirectUrl);
});

app.get('/external', (req, res) => {
  const targetUrl = req.query.url;
  
  // Validate domain allowlist
  const allowedDomains = ['example.com', 'trusted.com'];
  const parsed = url.parse(targetUrl);
  
  if (!allowedDomains.includes(parsed.hostname)) {
    return res.status(400).send('Invalid redirect domain');
  }
  
  res.redirect(targetUrl);
});
```