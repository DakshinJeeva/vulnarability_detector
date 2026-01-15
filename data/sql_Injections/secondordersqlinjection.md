VULNERABILITY: SQL_INJECTION
PATTERN: Second-order injection
CWE: CWE-89
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
Previously stored data from database (originally from user input)

SINK:
SQL queries using retrieved database values without re-sanitization

DESCRIPTION:
Second-order SQL Injection occurs when malicious input is safely stored
in the database but later retrieved and used unsafely in subsequent SQL
queries. The injection executes during data retrieval/reuse, not during
initial storage, making it harder to detect.

WHY_THIS_IS_DANGEROUS:
- Bypasses input validation at entry point
- Difficult to detect during testing
- Can remain dormant until triggered
- Developers assume stored data is trusted
- Violates principle of "validate on use"

DETECTION_RULE:
Flag when:
- Data retrieved from database used in query construction
- Retrieved values concatenated into new SQL queries
- No re-sanitization of database-sourced data
- Different code paths for storage versus retrieval

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Retrieved data used in parameterized queries
- Data re-validated before use in queries
- ORM handles both storage and subsequent queries

EXAMPLE_VULNERABLE_CODE:
```js
app.post('/register', (req, res) => {
  const username = req.body.username;
  db.query("INSERT INTO users (username) VALUES (?)", [username]);
});

app.get('/admin/logs', (req, res) => {
  const userId = req.query.id;
  db.query("SELECT username FROM users WHERE id=?", [userId], (err, user) => {
    const username = user[0].username;
    db.query(`SELECT * FROM logs WHERE username='${username}'`, (err, logs) => {
      res.json(logs);
    });
  });
});
```

EXAMPLE_SAFE_CODE:
```js
app.post('/register', (req, res) => {
  const username = req.body.username;
  db.query("INSERT INTO users (username) VALUES (?)", [username]);
});

app.get('/admin/logs', (req, res) => {
  const userId = req.query.id;
  db.query("SELECT username FROM users WHERE id=?", [userId], (err, user) => {
    const username = user[0].username;
    db.query("SELECT * FROM logs WHERE username=?", [username], (err, logs) => {
      res.json(logs);
    });
  });
});
```