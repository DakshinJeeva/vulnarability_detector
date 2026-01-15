VULNERABILITY: SQL_INJECTION
PATTERN: Boolean-based blind injection
CWE: CWE-89
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
User-controlled input (req.query, req.body, req.params, cookies)

SINK:
SQL execution where application behavior differs based on query true/false results

DESCRIPTION:
Boolean-based Blind SQL Injection exploits applications that don't display
query results but show different responses based on whether injected 
conditions evaluate to true or false, enabling data inference through 
behavioral observation.

WHY_THIS_IS_DANGEROUS:
- Data exfiltration without direct query output
- Bypasses error suppression mechanisms
- Can extract entire databases character-by-character
- Difficult to detect in application logs

DETECTION_RULE:
Flag when:
- User input concatenated into SQL WHERE clauses
- Application shows different responses for true/false conditions
- Query results control conditional logic (if/else, redirects)
- No query results displayed but behavior changes

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Parameterized queries used for all conditions
- Input validated with strict type checking
- ORM handles all query construction

EXAMPLE_VULNERABLE_CODE:
```js
app.get('/product', (req, res) => {
  const productId = req.query.id;
  db.query(`SELECT * FROM products WHERE id='${productId}'`, (err, result) => {
    if (result && result.length > 0) {
      res.send("Product found");
    } else {
      res.send("Product not found");
    }
  });
});
```

EXAMPLE_SAFE_CODE:
```js
app.get('/product', (req, res) => {
  const productId = req.query.id;
  db.query("SELECT * FROM products WHERE id=?", [productId], (err, result) => {
    if (result && result.length > 0) {
      res.send("Product found");
    } else {
      res.send("Product not found");
    }
  });
});
```