VULNERABILITY: SQL_INJECTION
PATTERN: Error-based injection
CWE: CWE-89
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
User-controlled input (req.query, req.body, req.params, req.headers)

SINK:
SQL execution where database errors are displayed to users

DESCRIPTION:
Error-based SQL Injection exploits verbose database error messages
that reveal structural information. Attackers intentionally trigger
errors containing table names, column names, database versions, and
data types to facilitate reconnaissance and targeted attacks.

WHY_THIS_IS_DANGEROUS:
- Database structure and schema disclosure
- Error messages leak sensitive metadata
- Database version information aids exploitation
- Can extract data directly through error messages
- Provides intelligence for advanced attacks

DETECTION_RULE:
Flag when:
- Database errors displayed to end users
- User input concatenated into queries
- Error messages contain SQL syntax or schema details
- Stack traces or technical errors visible to clients

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Generic error messages only ("An error occurred")
- Errors logged server-side, not sent to client
- Parameterized queries prevent injection
- Production mode suppresses error details

EXAMPLE_VULNERABLE_CODE:
```js
app.get('/user', (req, res) => {
  const userId = req.query.id;
  db.query(`SELECT * FROM users WHERE id=${userId}`, (err, result) => {
    if (err) {
      return res.status(500).send(err.message);
    }
    res.json(result);
  });
});
```

EXAMPLE_SAFE_CODE:
```js
app.get('/user', (req, res) => {
  const userId = req.query.id;
  if (!Number.isInteger(parseInt(userId))) {
    return res.status(400).send("Invalid user ID");
  }
  db.query("SELECT * FROM users WHERE id=?", [userId], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).send("An error occurred");
    }
    res.json(result);
  });
});
```