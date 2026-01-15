VULNERABILITY: SQL_INJECTION
PATTERN: Time-based blind injection
CWE: CWE-89
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
User-controlled input (req.query, req.body, req.params, req.headers)

SINK:
SQL execution functions where time-delay functions can be injected

DESCRIPTION:
Time-based Blind SQL Injection uses database time-delay functions
(SLEEP, WAITFOR, pg_sleep) to infer data. Attackers inject conditional
delays where response time reveals whether injected conditions are true,
enabling data extraction through timing analysis.

WHY_THIS_IS_DANGEROUS:
- Works when application shows identical outputs
- Bypasses all response-based security controls
- Can extract data from completely blind contexts
- Difficult to detect without timing analysis
- Works across multiple database systems

DETECTION_RULE:
Flag when:
- User input concatenated into SQL queries
- Database supports delay functions (SLEEP, pg_sleep, WAITFOR)
- No output differences but timing can be manipulated
- Query execution time observable by attacker

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Parameterized queries prevent function injection
- Query timeout limits enforced
- Input validation blocks SQL keywords and functions

EXAMPLE_VULNERABLE_CODE:
```js
app.get('/check', (req, res) => {
  const userId = req.query.id;
  db.query(`SELECT * FROM users WHERE id='${userId}'`, (err, result) => {
    res.send("Processed");
  });
});
```

EXAMPLE_SAFE_CODE:
```js
app.get('/check', (req, res) => {
  const userId = req.query.id;
  if (!Number.isInteger(parseInt(userId))) {
    return res.status(400).send("Invalid ID");
  }
  db.query("SELECT * FROM users WHERE id=?", [userId], (err, result) => {
    res.send("Processed");
  });
});
```