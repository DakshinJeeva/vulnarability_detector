VULNERABILITY: SQL_INJECTION
PATTERN: Classic string concatenation
CWE: CWE-89
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
User-controlled input (req.query, req.body, req.params)

SINK:
db.query(), db.execute(), connection.query(), pool.query()

DESCRIPTION:
SQL Injection occurs when untrusted user input is directly concatenated
into SQL query strings using the + operator, allowing attackers to 
modify query structure and logic.

WHY_THIS_IS_DANGEROUS:
- Authentication bypass via OR 1=1 conditions
- Unauthorized data access from any table
- Data modification or deletion
- Database schema enumeration

DETECTION_RULE:
Flag when:
- User-controlled input flows into SQL execution functions
- Query is constructed using + operator for string concatenation
- No parameterized query or prepared statement is used

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Parameterized queries with placeholders (?, $1) are used
- ORM parameter binding is used (Sequelize, TypeORM)
- Input is validated AND parameterized

EXAMPLE_VULNERABLE_CODE:
```js
app.get('/user', (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id=" + id, (err, result) => {
    res.json(result);
  });
});
```

EXAMPLE_SAFE_CODE:
```js
app.get('/user', (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id=?", [id], (err, result) => {
    res.json(result);
  });
});
```