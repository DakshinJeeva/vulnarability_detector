# Vulnerability Detector

A simple **AI-assisted static security analyzer** that detects common web vulnerabilities  
like **SQL Injection** and **XSS** using **Source → Sink analysis** and **RAG**.

---

## Why this project?

Traditional scanners only check patterns and often give false positives.

This tool answers:
- Where does the data come from?
- Where does it go?
- Why is it dangerous?
- How should it be fixed?

> **Security bugs are data-flow bugs.**

---

## How it works

1. Vulnerability patterns are stored as documents  
2. Documents are embedded and saved in a vector database  
3. Code is analyzed using Source → Sink logic  
4. Relevant vulnerability docs are retrieved (RAG)  
5. An LLM explains the issue and suggests a fix  

---
## Tools Used
### 🧠 AI & ML

HuggingFace Embeddings

Model: all-MiniLM-L6-v2

Purpose: Convert vulnerability documents and code into vector embeddings (offline)

LLM via OpenRouter

Model: mistralai/devstral-2512:free

Purpose: Reason about code, explain vulnerabilities, and suggest fixes

### 📚 Retrieval / RAG

Chroma (Vector Database)

Purpose: Store and retrieve embedded vulnerability documents

Used for: Retrieval-Augmented Generation (RAG)

LangChain (community modules)

Purpose:

Interface with Chroma

Manage embeddings

---

## ▶️ How to run

### 1️⃣ Install dependencies

pip install langchain chromadb sentence-transformers requests

### 2️⃣ Set API key

### 3️⃣ python analyze.py
---
### Sample Output 

💡 Analysis Result:

Here's the security analysis of the provided code:

### 1. `/search-users` endpoint
**Vulnerability**: SQL_INJECTION (Template literal injection) + XSS
**Source → Sink**:
- `req.query.term` → `db.query()` (SQL Injection)
- `searchTerm` → `res.send()` (XSS)

**Why vulnerable**:
- SQL: User input directly interpolated into query using template literals
- XSS: User input rendered in HTML without sanitization

**Fix**:
```js
app.get('/search-users', (req, res) => {
  const searchTerm = req.query.term;
  // SQL fix
  db.query("SELECT * FROM users WHERE username LIKE ?", [`%${searchTerm}%`], (err, users) => {
    // XSS fix
    res.send(`<h1>Results for: ${escapeHtml(searchTerm)}</h1>`);
  });
});
```

### 2. `/add-log` endpoint
**Vulnerability**: SQL_INJECTION (Classic concatenation)
**Source → Sink**:
- `req.body.action` + `req.body.details` → `db.query()`

**Why vulnerable**:
- Direct string concatenation with user input
- No parameterization

**Fix**:
```js
app.post('/add-log', (req, res) => {
  const action = req.body.action;
  const details = req.body.details;
  db.query("INSERT INTO logs (action, details) VALUES (?, ?)", [action, details]);
  res.send("Log added");
});
```

### 3. `/admin/logs` endpoint
**Vulnerability**: XSS
**Source → Sink**:
- `log.action` + `log.details` → `res.send()`

**Why vulnerable**:
- Database content (potentially from user input) rendered in HTML without sanitization

**Fix**:
```js
app.get('/admin/logs', (req, res) => {
  db.query("SELECT * FROM logs", (err, logs) => {
    let html = "";
    logs.forEach(log => {
      html += `<div>${escapeHtml(log.action)}: ${escapeHtml(log.details)}</div>`;
    });
    res.send(html);
  });
});
```

### 4. `/admin-login` endpoint
**Vulnerability**: SQL_INJECTION (Template literal) + XSS
**Source → Sink**:
- `req.body.username` → `db.query()` (SQL)
- `username` → `res.send()` (XSS)

**Why vulnerable**:
- SQL: Template literal with user input
- XSS: User input in HTML response

**Fix**:
```js
app.post('/admin-login', (req, res) => {
  const username = req.body.username;
  db.query("SELECT * FROM admins WHERE username=?", [username], (err, admin) => {
    if (!admin) {
      res.send(`<p>Login failed for: ${escapeHtml(username)}</p>`);
    }
  });
});
```

### 5. `/redirect` endpoint
**Vulnerabilities**:
1. SQL_INJECTION (Classic concatenation)
2. XSS (via `target` parameter)
3. Open Redirect (via `target` parameter)

**Source → Sink**:
- `req.query.userId` → `db.query()` (SQL)
- `req.query.url` → `res.send()` (XSS + Open Redirect)

**Why vulnerable**:
- SQL: Direct concatenation
- XSS: User input in HTML and JavaScript
- Open Redirect: Unvalidated URL in redirect

**Fix**:
```js
app.get('/redirect', (req, res) => {
  const target = req.query.url;
  const userId = req.query.userId;

  // SQL fix
  db.query("SELECT * FROM users WHERE id=?", [userId], (err, user) => {
    // Validate target URL
    const safeTarget = validateUrl(target) || '/default';
    res.send(`
      <p>Redirecting to: ${escapeHtml(safeTarget)}</p>
      <script>window.location="${escapeJs(safeTarget)}";</script>
    `);
  });
});
```

### Summary of Issues Found:
1. Multiple SQL Injection vulnerabilities (3 different patterns)
2. Multiple XSS vulnerabilities (5 instances)
3. One Open Redirect vulnerability

### General Recommendations:
1. Always use parameterized queries
2. Implement input validation and output encoding
3. Use security libraries like:
   - `validator` for input validation
   - `xss` or `escape-html` for output encoding
4. Consider using ORMs that handle parameterization automatically
5. Implement CSP headers to mitigate XSS impact
---

