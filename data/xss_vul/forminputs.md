VULNERABILITY: XSS
PATTERN: Reflected XSS via form inputs
CWE: CWE-79
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
Form input fields reflected back (req.body.email, req.body.username, search boxes)

SINK:
Form re-display with error messages or pre-filled values

DESCRIPTION:
Reflected XSS via form inputs occurs when form data is immediately
reflected back in error messages, validation feedback, or pre-filled
input values without proper encoding. This often happens in login
errors and contact forms.

WHY_THIS_IS_DANGEROUS:
- Common in login and registration forms
- Error messages often bypass sanitization
- Pre-filled values use vulnerable attributes
- Can capture credentials on fake error pages
- Social engineering makes exploitation easier

DETECTION_RULE:
Flag when:
- Form data reflected in error messages
- Input values pre-filled with user data
- Validation errors echo unsanitized input
- HTML attributes populated with form data

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Error messages use static strings only
- Template engines auto-escape error data
- Input values sanitized before re-display
- Attribute context properly encoded

EXAMPLE_VULNERABLE_CODE:
```js
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  
  db.query("SELECT * FROM users WHERE username=?", [username], 
    (err, user) => {
      if (!user || user.length === 0) {
        res.send(`
          <p>Login failed for user: ${username}</p>
          <form>
            <input name="username" value="${username}">
            <input name="password" type="password">
            <button>Login</button>
          </form>
        `);
      }
    });
});
```

EXAMPLE_SAFE_CODE:
```js
const escapeHtml = require('escape-html');

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  
  db.query("SELECT * FROM users WHERE username=?", [username], 
    (err, user) => {
      if (!user || user.length === 0) {
        res.render('login', { 
          error: 'Login failed',
          username: escapeHtml(username)
        });
      }
    });
});
```