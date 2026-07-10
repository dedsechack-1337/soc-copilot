"""
Semantic lookup against the embedded MITRE ATT&CK corpus.

Given a free-text behavior description (e.g. "process dumping lsass.exe
memory then exfiltrating over DNS"), returns the most likely ATT&CK
technique(s) with IDs, tactics, and confidence-ranked similarity.

This is intentionally retrieval-only (no LLM call) for the mapping step --
it's fast, cheap, deterministic, and the vector similarity score is usually
sufficient signal on its own. The calling agent can pass the result to the
LLM afterward for a natural-language summary if needed.
"""
from pathlib import Path

from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

BASE_DIR = Path(__file__).resolve().parent.parent
PERSIST_DIR = str(BASE_DIR / "vectorstore" / "attack_chroma")
COLLECTION_NAME = "mitre_attack"
EMBED_MODEL = "nomic-embed-text"

_vectorstore = None


def _get_vectorstore() -> Chroma:
    global _vectorstore
    if _vectorstore is None:
        embeddings = OllamaEmbeddings(model=EMBED_MODEL)
        _vectorstore = Chroma(
            collection_name=COLLECTION_NAME,
            embedding_function=embeddings,
            persist_directory=PERSIST_DIR,
        )
    return _vectorstore


def lookup_attack_technique(behavior_description: str, k: int = 5) -> list[dict]:
    """
    Return the top-k ATT&CK techniques whose descriptions best match the
    given behavior description, ranked by similarity (lower distance = better).
    """
    vs = _get_vectorstore()
    results = vs.similarity_search_with_relevance_scores(behavior_description, k=k)

    mapped = []
    for doc, score in results:
        mapped.append(
            {
                "technique_id": doc.metadata["technique_id"],
                "name": doc.metadata["name"],
                "tactics": doc.metadata["tactics"],
                "url": doc.metadata["url"],
                "relevance_score": round(score, 4),
                "excerpt": doc.page_content.split("\n\n", 1)[-1][:280],
            }
        )
    return mapped


def format_for_chat(results: list[dict]) -> str:
    """Render lookup results as a readable markdown table for the chat UI."""
    if not results:
        return "No matching ATT&CK techniques found."
    lines = ["| Technique | Name | Tactic(s) | Relevance |",
             "|---|---|---|---|"]
    for r in results:
        lines.append(
            f"| [{r['technique_id']}]({r['url']}) | {r['name']} | "
            f"{r['tactics']} | {r['relevance_score']} |"
        )
    return "\n".join(lines)


# LangChain tool wrapper -- imported by agent.py
from langchain_core.tools import tool  # noqa: E402


@tool
def mitre_attack_lookup(behavior_description: str) -> str:
    """
    Map a described adversary behavior or TTP to MITRE ATT&CK technique IDs.
    Input should be a natural-language description of the observed or
    suspected behavior, e.g. 'dumping credentials from LSASS process memory'.
    Returns the top matching technique IDs, names, tactics, and relevance.
    """
    results = lookup_attack_technique(behavior_description, k=5)
    return format_for_chat(results)


if __name__ == "__main__":
    import sys
    query = " ".join(sys.argv[1:]) or "dumping lsass memory to steal credentials"
    for r in lookup_attack_technique(query):
        print(r)
