"""
Embed ATT&CK technique records into a persistent ChromaDB collection.

Uses Ollama's embedding model (default: nomic-embed-text) so the whole
pipeline stays local -- no data leaves the box.

Prereqs:
    ollama pull nomic-embed-text
    (ollama serve running on localhost:11434)

Run:
    python ingest/build_vectorstore.py
"""
import json
from pathlib import Path

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_ollama import OllamaEmbeddings

BASE_DIR = Path(__file__).resolve().parent.parent
TECHNIQUES_FILE = BASE_DIR / "data" / "techniques.json"
PERSIST_DIR = str(BASE_DIR / "vectorstore" / "attack_chroma")
COLLECTION_NAME = "mitre_attack"
EMBED_MODEL = "nomic-embed-text"


def load_documents() -> list[Document]:
    records = json.loads(TECHNIQUES_FILE.read_text())
    docs = []
    for r in records:
        # The embedded text combines name + tactics + description so semantic
        # search matches on behavior, not just keyword overlap with the ID.
        content = (
            f"{r['technique_id']} - {r['name']}\n"
            f"Tactics: {', '.join(r['tactics'])}\n"
            f"Platforms: {', '.join(r['platforms'])}\n\n"
            f"{r['description']}"
        )
        docs.append(
            Document(
                page_content=content,
                metadata={
                    "technique_id": r["technique_id"],
                    "name": r["name"],
                    "tactics": ", ".join(r["tactics"]),
                    "is_subtechnique": r["is_subtechnique"],
                    "url": r["url"],
                },
            )
        )
    return docs


def build(embed_model: str = EMBED_MODEL, persist_dir: str = PERSIST_DIR) -> Chroma:
    docs = load_documents()
    print(f"Embedding {len(docs)} ATT&CK technique documents with '{embed_model}'...")
    embeddings = OllamaEmbeddings(model=embed_model)
    vectorstore = Chroma.from_documents(
        documents=docs,
        embedding=embeddings,
        collection_name=COLLECTION_NAME,
        persist_directory=persist_dir,
    )
    print(f"Vector store persisted to {persist_dir}")
    return vectorstore


if __name__ == "__main__":
    build()
