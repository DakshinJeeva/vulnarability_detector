VULNERABILITY: XSS
PATTERN: Reflected XSS via URL parameters
CWE: CWE-79
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
URL query parameters (req.query.q, req.query.search, req.query.term)

SINK:
Direct reflection in HTML response without encoding

DESCRIPTION:
Reflected XSS via URL parameters occurs when user input from URL query
strings is immediately reflected in the HTML response without proper
encoding. Attackers craft malicious URLs that execute scripts when
victims click the link.

WHY_THIS_IS_DANGEROUS:
- Easy to exploit via phishing emails
- Can bypass URL filters if encoded
- No database storage needed
- Victims often trust familiar domains
- Can steal tokens from URL fragments

DETECTION_RULE:
Flag when:
- URL parameters directly embedded in HTML
- Query values used in response without encoding
- Search results show unsanitized query string
- Error pages echo URL parameters

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Parameters encoded with escapeHtml or textContent
- Template engines auto-escape parameters
- Input validated against strict allowlist
- Content Security Policy prevents inline execution

EXAMPLE_VULNERABLE_CODE:
```js
app.get('/search', (req, res) => {
  const query = req.query.q;
  
  db.query("SELECT * FROM products WHERE name LIKE ?", [`%${query}%`], 
    (err, results) => {
      res.send(`
        <h1>Search Results for: ${query}</h1>
        <p>Found ${results.length} results</p>
      `);
    });
});
```

EXAMPLE_SAFE_CODE:
```js
const escapeHtml = require('escape-html');

app.get('/search', (req, res) => {
  const query = escapeHtml(req.query.q);
  
  db.query("SELECT * FROM products WHERE name LIKE ?", [`%${req.query.q}%`], 
    (err, results) => {
      res.render('search', { query, results }); // Template auto-escapes
    });
});
```