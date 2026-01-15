import os
import requests

from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings

# 1️⃣ Load embeddings
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

# 2️⃣ Load Chroma vector store (UPDATED COLLECTION NAME)
vectorstore = Chroma(
    embedding_function=embeddings,
    collection_name="web-vulnerabilities",
    persist_directory="./chroma_db"
)

# 3️⃣ Create retriever
retriever = vectorstore.as_retriever(search_kwargs={"k": 3})

# 4️⃣ Code snippet to analyze
code_snippet = """
const express = require('express');
const app = express();

app.get('/search-users', (req, res) => {
  const searchTerm = req.query.term;
  db.query(`SELECT * FROM users WHERE username LIKE '%${searchTerm}%'`, 
    (err, users) => {
      res.send(`<h1>Results for: ${searchTerm}</h1>`); // Also XSS
    });
});

app.post('/add-log', (req, res) => {
  const action = req.body.action;
  const details = req.body.details;
  db.query("INSERT INTO logs (action, details) VALUES ('" + action + "', '" + details + "')");
  res.send("Log added");
});

app.get('/admin/logs', (req, res) => {
  db.query("SELECT * FROM logs", (err, logs) => {
    let html = "";
    logs.forEach(log => {
      html += `<div>${log.action}: ${log.details}</div>`; // XSS when displayed
    });
    res.send(html);
  });
});

app.post('/admin-login', (req, res) => {
  const username = req.body.username;
  db.query(`SELECT * FROM admins WHERE username='${username}'`, (err, admin) => {
    if (!admin) {
      res.send(`<p>Login failed for: ${username}</p>`); // XSS
    }
  });
});

app.get('/redirect', (req, res) => {
  const target = req.query.url;
  const userId = req.query.userId;
  
  db.query("SELECT * FROM users WHERE id=" + userId, (err, user) => { // SQL Injection
    res.send(`
      <p>Redirecting to: ${target}</p>
      <script>window.location="${target}";</script>
    `); // XSS
  });
});
"""

# 5️⃣ Retrieve relevant vulnerability documents
docs = retriever.invoke(code_snippet)

# 6️⃣ Prepare references
references = "\n".join([d.page_content for d in docs])

prompt = f"""
You are a security code analyzer.

Reference vulnerabilities:
{references}

Analyze this code:
{code_snippet}

Answer:
1. Vulnerability name (or NONE)
2. Source → Sink data flow
3. Why it is vulnerable
4. How to fix
"""

API_KEY = os.getenv("OPENROUTER_API_KEY")

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
    "HTTP-Referer": "http://localhost",
    "X-Title": "Security Code Analyzer"
}

data = {
    "model": "mistralai/devstral-2512:free",
    "messages": [
        {"role": "system", "content": "You are a security code analyzer."},
        {"role": "user", "content": prompt}
    ]
}

response = requests.post(
    "https://openrouter.ai/api/v1/chat/completions",
    headers=headers,
    json=data,
    timeout=60
)

# HTTP-level validation
if response.status_code != 200:
    raise RuntimeError(f"HTTP {response.status_code}: {response.text}")

# JSON parsing
try:
    res = response.json()
except Exception:
    raise RuntimeError(f"Invalid JSON response: {response.text}")

# API-level error handling
if "error" in res:
    raise RuntimeError(f"API Error: {res['error']}")

# Extract response safely
answer = (
    res.get("choices", [{}])[0]
       .get("message", {})
       .get("content")
)

if not answer:
    raise RuntimeError(f"Empty or unknown response format: {res}")

print("💡 Analysis Result:\n")
print(answer)

