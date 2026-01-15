VULNERABILITY: XSS
PATTERN: Reflected XSS via HTTP headers
CWE: CWE-79
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
HTTP request headers (User-Agent, Referer, Cookie, X-Forwarded-For)

SINK:
Error pages, analytics dashboards, log viewers displaying headers

DESCRIPTION:
Reflected XSS via HTTP headers occurs when attacker-controlled headers
like User-Agent or Referer are reflected in responses without encoding.
This is common in error pages, debugging tools, and analytics dashboards
that display request information.

WHY_THIS_IS_DANGEROUS:
- Headers fully controlled by attackers
- Often overlooked in security reviews
- Common in admin/debug interfaces
- Can target administrators viewing logs
- Difficult to detect in automated scans

DETECTION_RULE:
Flag when:
- Request headers displayed in error pages
- User-Agent shown in analytics dashboards
- Referer reflected in response
- Custom headers echoed without encoding

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Headers sanitized before display
- Template engines auto-escape header data
- Debug mode disabled in production
- Headers logged server-side only

EXAMPLE_VULNERABLE_CODE:
```js
app.use((req, res, next) => {
  const userAgent = req.headers['user-agent'];
  const referer = req.headers['referer'];
  
  db.query("INSERT INTO analytics (user_agent, referer, path) VALUES (?, ?, ?)",
    [userAgent, referer, req.path]);
  
  next();
});

app.get('/admin/analytics', requireAdmin, (req, res) => {
  db.query("SELECT * FROM analytics LIMIT 100", (err, data) => {
    let html = "<table>";
    data.forEach(row => {
      html += `<tr>
        <td>${row.user_agent}</td>
        <td>${row.referer}</td>
        <td>${row.path}</td>
      </tr>`;
    });
    html += "</table>";
    res.send(html);
  });
});
```

EXAMPLE_SAFE_CODE:
```js
const escapeHtml = require('escape-html');

app.use((req, res, next) => {
  const userAgent = req.headers['user-agent'];
  const referer = req.headers['referer'];
  
  db.query("INSERT INTO analytics (user_agent, referer, path) VALUES (?, ?, ?)",
    [userAgent, referer, req.path]);
  
  next();
});

app.get('/admin/analytics', requireAdmin, (req, res) => {
  db.query("SELECT * FROM analytics LIMIT 100", (err, data) => {
    res.render('admin/analytics', { data }); // Template auto-escapes
  });
});
```