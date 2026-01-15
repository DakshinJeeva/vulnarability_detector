import os
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings

BASE_DIR = "./data"
PERSIST_DIR = "./chroma_db"
COLLECTION_NAME = "web-vulnerabilities"

texts = []
metadatas = []

# FREE offline embeddings
embeddings = HuggingFaceEmbeddings(
    model_name="all-MiniLM-L6-v2"
)

doc_id = 0

for vuln_type in os.listdir(BASE_DIR):
    vuln_path = os.path.join(BASE_DIR, vuln_type)

    if not os.path.isdir(vuln_path):
        continue

    for file in os.listdir(vuln_path):
        if file.endswith(".md"):
            with open(os.path.join(vuln_path, file), "r", encoding="utf-8") as f:
                texts.append(f.read())
                metadatas.append({
                    "id": doc_id,
                    "vulnerability": vuln_type.upper(),   # SQL_INJECTION / XSS
                    "pattern": file.replace(".md", "").upper(),
                    "language": "JavaScript",
                    "severity": "HIGH",
                    "source": file
                })
                doc_id += 1

print(f"Loaded {len(texts)} vulnerability documents")

vectorstore = Chroma.from_texts(
    texts=texts,
    embedding=embeddings,
    metadatas=metadatas,
    collection_name=COLLECTION_NAME,
    persist_directory=PERSIST_DIR
)

vectorstore.persist()
print("embedded into vector database")
