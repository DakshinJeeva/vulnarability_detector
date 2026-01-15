🛡️ Vulnerability Detector (RAG-Powered Security Analyzer)

A context-aware security analysis tool that detects web vulnerabilities (SQL Injection, XSS, Open Redirect, etc.) using:

🔍 Static analysis concepts (Source → Sink)

🧠 Retrieval-Augmented Generation (RAG)

🤖 LLM-based reasoning

📚 Offline CWE-style vulnerability knowledge

Unlike traditional pattern-matching scanners, this tool understands why a vulnerability exists and explains how to fix it.

🚩 Why This Tool Exists

Traditional SAST tools often:

Produce false positives

Give generic explanations

Fail on context-dependent logic

This project was built to answer real developer questions:

❓ Why is this vulnerable?
❓ Where does the unsafe data come from?
❓ How exactly should I fix it?

✅ What this tool does differently

Tracks user-controlled data (Source)

Tracks dangerous operations (Sink)

Uses real vulnerability knowledge as context

Uses an LLM to reason, not just match patterns

🧠 Core Concept
Source → Sink + RAG

A vulnerability exists only if:

User-Controlled Input (SOURCE)
        ↓
     Program Flow
        ↓
Dangerous Operation (SINK)


This tool combines that with retrieved vulnerability references to improve accuracy and explanation quality.

🔁 High-Level Flow (How It Works)
Developer Code
     ↓
Chunked & Analyzed
     ↓
Relevant Vulnerability Docs Retrieved (RAG)
     ↓
LLM Reasons with Code + Security Context
     ↓
Structured Security Report

📊 Flow Chart (End-to-End)
flowchart TD
    A[Developer Code Snippet] --> B[Embedding Model]
    B --> C[Vector Search - Chroma DB]
    C --> D[Relevant Vulnerability Docs]

    A --> E[Prompt Builder]
    D --> E

    E --> F[LLM via OpenRouter]
    F --> G[Security Analysis Output]

    G --> H[Vulnerability Name]
    G --> I[Source → Sink Flow]
    G --> J[Why Vulnerable]
    G --> K[How to Fix]

🏗️ Architecture Overview
1️⃣ Knowledge Ingestion (Offline)

Vulnerability patterns stored as .md files

Embedded using MiniLM

Stored in Chroma vector database

data/
 ├── sql_injection/
 │    ├── concat_query.md
 │    └── template_literal.md
 ├── xss/
 │    ├── reflected.md
 │    └── stored.md

2️⃣ Retrieval (RAG)

When code is analyzed:

Code snippet is embedded

Similar vulnerability docs are retrieved

These docs are injected into the LLM prompt

This grounds the LLM in security facts.

3️⃣ Reasoning (LLM)

The LLM receives:

Code snippet

Retrieved vulnerability references

A structured analysis prompt

It produces:

Vulnerability name

Source → Sink data flow

Why it’s vulnerable

How to fix it

🧪 Example Output
Vulnerability: SQL_INJECTION

Source → Sink:
req.query.term → db.query()

Why vulnerable:
User input is concatenated directly into a SQL query without parameterization,
allowing attackers to inject arbitrary SQL.

How to fix:
Use parameterized queries or ORM bindings to prevent SQL execution of user input.

🧰 Tech Stack
Component	Technology
Language	Python
Embeddings	all-MiniLM-L6-v2
Vector DB	Chroma
LLM Access	OpenRouter
Model	mistralai/devstral-2512 (free)
Analysis Type	Static + RAG
▶️ How to Run
1️⃣ Install dependencies
pip install langchain chromadb sentence-transformers requests

2️⃣ Set API key
export OPENROUTER_API_KEY="sk-or-xxxx"

3️⃣ Build vector database
python ingest_vulnerabilities.py

4️⃣ Run analysis
python analyze_code.py

🚫 What This Tool Is NOT

❌ Not a regex scanner
❌ Not a runtime (DAST) tool
❌ Not just an LLM guessing vulnerabilities

✅ What This Tool IS

✔ A semantic security analyzer
✔ A teaching tool for secure coding
✔ A low-false-positive SAST assistant
✔ A foundation for advanced security tooling

🔮 Future Improvements

 Multi-language support (Python, Java, PHP)

 Severity scoring (CVSS)

 Semgrep / CodeQL rule generation

 VS Code extension

 CI/CD integration

🎯 Ideal Use Cases

Security learning & research

Secure code reviews

AI-assisted SAST experimentation

Final year / resume-grade project

🧑‍💻 Author

Dakshin Jeeva
Security + AI + Systems Engineering Enthusiast
