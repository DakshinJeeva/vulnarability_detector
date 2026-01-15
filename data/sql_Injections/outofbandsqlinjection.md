VULNERABILITY: SQL_INJECTION
PATTERN: Out-of-band injection
CWE: CWE-89
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
User-controlled input (req.query, req.body, req.params)

SINK:
SQL execution with database external network capabilities enabled

DESCRIPTION:
Out-of-Band SQL Injection exploits database features that trigger
external network connections (DNS, HTTP, SMB) to attacker-controlled
servers. Data is exfiltrated through these side channels rather than
application responses, using functions like xp_dirtree, LOAD_FILE, UTL_HTTP.

WHY_THIS_IS_DANGEROUS:
- Works when in-band retrieval is impossible
- Bypasses application-level output controls
- Can exfiltrate data with no visible response changes
- Enables file system access and command execution
- Difficult to detect without network monitoring

DETECTION_RULE:
Flag when:
- User input reaches SQL queries
- Database has external network functions enabled
- String concatenation allows function injection
- Functions like xp_dirtree, LOAD_FILE, UTL_HTTP present

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Parameterized queries prevent function injection
- Database network functions disabled
- Network egress restricted at firewall
- Database runs with least privilege

EXAMPLE_VULNERABLE_CODE:
```js
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  db.query(`SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`, 
    (err, result) => {
      res.json(result);
    });
});
```

EXAMPLE_SAFE_CODE:
```js
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  db.query("SELECT * FROM products WHERE name LIKE ?", 
    [`%${searchTerm}%`], 
    (err, result) => {
      res.json(result);
    });
});
```