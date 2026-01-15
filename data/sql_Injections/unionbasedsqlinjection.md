VULNERABILITY: SQL_INJECTION
PATTERN: Union-based injection
CWE: CWE-89
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
User-controlled input (req.query, req.body, req.params)

SINK:
SQL SELECT queries that display results, executed via db.query()

DESCRIPTION:
Union-based SQL Injection exploits the UNION operator to combine the
original query results with attacker-controlled SELECT statements,
allowing direct extraction of data from arbitrary tables by appending
UNION SELECT to the vulnerable query.

WHY_THIS_IS_DANGEROUS:
- Direct extraction of sensitive data from any table
- Can retrieve passwords, credit cards, personal information
- Bypasses application access controls
- Fast and efficient data exfiltration
- Can enumerate entire database schema

DETECTION_RULE:
Flag when:
- User input flows into SELECT queries with displayed results
- String concatenation or template literals build query
- Application renders query results to user
- UNION keyword can be injected through input

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Parameterized queries prevent UNION injection
- ORM query builders handle all query construction
- Input validation blocks SQL keywords (UNION, SELECT)

EXAMPLE_VULNERABLE_CODE:
```js
app.get('/products', (req, res) => {
  const category = req.query.category;
  db.query(`SELECT name, price FROM products WHERE category='${category}'`, 
    (err, result) => {
      res.json(result);
    });
});
```

EXAMPLE_SAFE_CODE:
```js
app.get('/products', (req, res) => {
  const category = req.query.category;
  db.query("SELECT name, price FROM products WHERE category=?", 
    [category], 
    (err, result) => {
      res.json(result);
    });
});
```