VULNERABILITY: SQL_INJECTION
PATTERN: Template literal injection
CWE: CWE-89
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
User-controlled input (req.query, req.body, req.params)

SINK:
db.query(), db.execute(), connection.query(), pool.query()

DESCRIPTION:
SQL Injection occurs when untrusted user input is embedded into SQL
queries using template literals (backticks with ${}) without proper
parameterization, allowing attackers to inject malicious SQL code.

WHY_THIS_IS_DANGEROUS:
- Modern syntax gives false sense of security
- Direct string interpolation bypasses protection
- Authentication bypass possible
- Full database compromise potential

DETECTION_RULE:
Flag when:
- User-controlled input flows into SQL execution functions
- Query uses template literals with ${variable} interpolation
- No parameterized query or prepared statement is used

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Template literals used only for static parts of query
- Variables passed through parameter array [var1, var2]
- ORM query builders handle parameterization

EXAMPLE_VULNERABLE_CODE:
```js
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  db.query(`SELECT * FROM users WHERE username='${username}' AND password='${password}'`, 
    (err, result) => {
      res.json(result);
    });
});
```

EXAMPLE_SAFE_CODE:
```js
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  db.query("SELECT * FROM users WHERE username=? AND password=?", 
    [username, password], 
    (err, result) => {
      res.json(result);
    });
});
```