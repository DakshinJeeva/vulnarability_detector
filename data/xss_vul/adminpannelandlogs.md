VULNERABILITY: XSS
PATTERN: Stored XSS in admin panel and logs
CWE: CWE-79
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
User input stored in logs (error logs, activity logs, audit trails)

SINK:
Admin dashboard rendering log entries without encoding

DESCRIPTION:
Stored XSS in admin panels occurs when user-controlled data is logged
and later displayed in administrative interfaces without sanitization.
Attackers inject scripts that execute when admins view logs, enabling
privilege escalation and admin account compromise.

WHY_THIS_IS_DANGEROUS:
- Targets high-privilege admin accounts
- Can lead to full application compromise
- Admins often trusted, defenses relaxed
- Session hijacking grants admin access
- Can modify system configurations

DETECTION_RULE:
Flag when:
- User input logged without encoding
- Admin panels render logs directly to HTML
- Error messages include unsanitized user input
- Activity logs display raw request data

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Logs sanitized before display
- Admin interface uses textContent instead of innerHTML
- Template engines auto-escape log data
- Separate logging system with output encoding

EXAMPLE_VULNERABLE_CODE:
```js
app.post('/login', (req, res) => {
  const username = req.body.username;
  const ip = req.ip;
  
  // Log failed login
  db.query("INSERT INTO audit_logs (action, details) VALUES (?, ?)", 
    ['login_failed', `User ${username} from ${ip}`]);
  
  res.status(401).send("Login failed");
});

app.get('/admin/logs', requireAdmin, (req, res) => {
  db.query("SELECT * FROM audit_logs", (err, logs) => {
    let html = "<table>";
    logs.forEach(log => {
      html += `<tr><td>${log.action}</td><td>${log.details}</td></tr>`;
    });
    html += "</table>";
    res.send(html);
  });
});
```

EXAMPLE_SAFE_CODE:
```js
const escapeHtml = require('escape-html');

app.post('/login', (req, res) => {
  const username = escapeHtml(req.body.username);
  const ip = req.ip;
  
  db.query("INSERT INTO audit_logs (action, details) VALUES (?, ?)", 
    ['login_failed', `User ${username} from ${ip}`]);
  
  res.status(401).send("Login failed");
});

app.get('/admin/logs', requireAdmin, (req, res) => {
  db.query("SELECT * FROM audit_logs", (err, logs) => {
    res.render('admin/logs', { logs }); // Template auto-escapes
  });
});
```