VULNERABILITY: SQL_INJECTION
PATTERN: ORDER BY clause injection
CWE: CWE-89
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
User-controlled sorting parameters (req.query.sort, req.query.orderBy)

SINK:
SQL ORDER BY clauses in db.query()

DESCRIPTION:
ORDER BY clause injection occurs when user-controlled input is used
to specify sort columns or direction without validation. Since ORDER BY
cannot use parameterized placeholders in most databases, developers
often concatenate values directly, enabling injection attacks.

WHY_THIS_IS_DANGEROUS:
- Can lead to conditional data extraction
- Enable blind SQL injection attacks
- Difficult to parameterize in standard SQL
- Often overlooked in security reviews
- Can cause performance degradation (DoS)

DETECTION_RULE:
Flag when:
- User input directly concatenated into ORDER BY clause
- No whitelist validation of column names
- Sort direction (ASC/DESC) not validated
- Column numbers or expressions allowed without validation

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Column names validated against strict whitelist
- Input sanitized and matched to allowed columns
- ORM with safe sorting methods used

EXAMPLE_VULNERABLE_CODE:
```js
app.get('/users', (req, res) => {
  const sortBy = req.query.sort || 'name';
  const order = req.query.order || 'ASC';
  db.query(`SELECT * FROM users ORDER BY ${sortBy} ${order}`, 
    (err, result) => {
      res.json(result);
    });
});
```

EXAMPLE_SAFE_CODE:
```js
app.get('/users', (req, res) => {
  const sortBy = req.query.sort || 'name';
  const order = req.query.order || 'ASC';
  
  const allowedColumns = ['name', 'email', 'created_at'];
  const allowedOrders = ['ASC', 'DESC'];
  
  if (!allowedColumns.includes(sortBy) || !allowedOrders.includes(order.toUpperCase())) {
    return res.status(400).send("Invalid sort parameters");
  }
  
  db.query(`SELECT * FROM users ORDER BY ${sortBy} ${order}`, 
    (err, result) => {
      res.json(result);
    });
});
```