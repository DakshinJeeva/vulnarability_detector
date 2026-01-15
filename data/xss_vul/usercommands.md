VULNERABILITY: XSS
PATTERN: Stored XSS via user comments
CWE: CWE-79
OWASP: A03:2021-Injection
LANGUAGE: JavaScript (Node.js)

SOURCE:
User-generated content (req.body.comment, req.body.message, req.body.post)

SINK:
Database storage followed by HTML rendering without sanitization

DESCRIPTION:
Stored XSS via user comments occurs when malicious scripts are saved
to the database through comment fields and later rendered to all users
viewing the page without proper output encoding. The script executes
persistently for every visitor.

WHY_THIS_IS_DANGEROUS:
- Affects all users who view the content
- Persists until removed from database
- Can steal session cookies and credentials
- Enables account takeover attacks
- Can spread like a worm in social features

DETECTION_RULE:
Flag when:
- User input stored in database without sanitization
- Stored content rendered to HTML without encoding
- No Content Security Policy headers
- innerHTML, dangerouslySetInnerHTML used with user content

FALSE_POSITIVE_GUARD:
Do NOT flag if:
- Input sanitized with DOMPurify or similar library
- Output encoded using htmlspecialchars or textContent
- Template engines auto-escape by default (EJS with <%= %>)
- Content Security Policy blocks inline scripts

EXAMPLE_VULNERABLE_CODE:
```js
app.post('/comment', (req, res) => {
  const comment = req.body.comment;
  db.query("INSERT INTO comments (text) VALUES (?)", [comment]);
  res.send("Comment posted");
});

app.get('/comments', (req, res) => {
  db.query("SELECT * FROM comments", (err, comments) => {
    let html = "<div>";
    comments.forEach(c => {
      html += `<p>${c.text}</p>`;
    });
    html += "</div>";
    res.send(html);
  });
});
```

EXAMPLE_SAFE_CODE:
```js
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

app.post('/comment', (req, res) => {
  const comment = DOMPurify.sanitize(req.body.comment);
  db.query("INSERT INTO comments (text) VALUES (?)", [comment]);
  res.send("Comment posted");
});

app.get('/comments', (req, res) => {
  db.query("SELECT * FROM comments", (err, comments) => {
    res.render('comments', { comments }); // EJS auto-escapes with <%= %>
  });
});
```