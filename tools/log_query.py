"""
Natural-language querying of security logs.

Real deployments should point this at your actual SIEM (Elasticsearch,
Splunk, etc.). This module ships with:
  1. An LLM-based NL -> Elasticsearch Query DSL translator
  2. A MockLogBackend with a small synthetic dataset so the whole agent
     is runnable and testable without a live SIEM connection.

Swap MockLogBackend for a real elasticsearch.Elasticsearch client in
production (see ElasticsearchBackend stub below).
"""
import json
import re
from datetime import datetime, timedelta

from langchain_core.tools import tool
from langchain_ollama import ChatOllama

LLM_MODEL = "llama3.1"

SCHEMA_DESCRIPTION = """
Index: security-logs-*
Fields:
  @timestamp        (date)
  event.category     (keyword: authentication, process, network, file)
  event.outcome       (keyword: success, failure)
  user.name           (keyword)
  source.ip           (ip)
  destination.ip      (ip)
  destination.port     (long)
  process.name          (keyword, e.g. powershell.exe)
  process.command_line   (text)
  host.name               (keyword)
"""

NL2DSL_SYSTEM_PROMPT = f"""You translate analyst questions into Elasticsearch
Query DSL (as JSON) against this index schema:

{SCHEMA_DESCRIPTION}

Output ONLY a valid Elasticsearch query JSON body (the object that would go
in the request body's "query" field, plus optional "sort" and "size").
No commentary, no markdown fences.
"""


def nl_to_dsl(question: str, llm_model: str = LLM_MODEL) -> dict:
    llm = ChatOllama(model=llm_model, temperature=0.0)
    messages = [
        ("system", NL2DSL_SYSTEM_PROMPT),
        ("user", question),
    ]
    response = llm.invoke(messages)
    text = response.content.strip()
    text = re.sub(r"^```(?:json)?\n", "", text)
    text = re.sub(r"\n```$", "", text)
    return json.loads(text)


# ---------------------------------------------------------------------------
# Mock backend -- synthetic data so the agent is demoable without a live SIEM
# ---------------------------------------------------------------------------
class MockLogBackend:
    def __init__(self):
        now = datetime.utcnow()
        self.events = [
            {
                "@timestamp": (now - timedelta(hours=2)).isoformat(),
                "event.category": "authentication",
                "event.outcome": "failure",
                "user.name": "jsmith",
                "source.ip": "203.0.113.45",
                "host.name": "dc01",
            },
            {
                "@timestamp": (now - timedelta(hours=2, minutes=1)).isoformat(),
                "event.category": "authentication",
                "event.outcome": "failure",
                "user.name": "jsmith",
                "source.ip": "203.0.113.45",
                "host.name": "dc01",
            },
            {
                "@timestamp": (now - timedelta(hours=2, minutes=2)).isoformat(),
                "event.category": "authentication",
                "event.outcome": "success",
                "user.name": "jsmith",
                "source.ip": "203.0.113.45",
                "host.name": "dc01",
            },
            {
                "@timestamp": (now - timedelta(minutes=30)).isoformat(),
                "event.category": "process",
                "event.outcome": "success",
                "user.name": "jsmith",
                "process.name": "powershell.exe",
                "process.command_line": "powershell.exe -enc SQBFAFgAKAB...",
                "host.name": "ws-104",
            },
        ]

    def search(self, dsl_query: dict, size: int = 20) -> list[dict]:
        """Extremely simplified 'match everything' mock -- returns all
        events, real backend would actually execute the DSL query."""
        return self.events[:size]


_backend = MockLogBackend()


# ---------------------------------------------------------------------------
# Real backend stub -- fill in for production use
# ---------------------------------------------------------------------------
class ElasticsearchBackend:
    def __init__(self, hosts: list[str], index_pattern: str = "security-logs-*"):
        from elasticsearch import Elasticsearch  # pip install elasticsearch
        self.client = Elasticsearch(hosts)
        self.index_pattern = index_pattern

    def search(self, dsl_query: dict, size: int = 20) -> list[dict]:
        body = {"query": dsl_query.get("query", dsl_query), "size": size}
        if "sort" in dsl_query:
            body["sort"] = dsl_query["sort"]
        resp = self.client.search(index=self.index_pattern, body=body)
        return [hit["_source"] for hit in resp["hits"]["hits"]]


@tool
def query_security_logs(question: str) -> str:
    """
    Answer a natural-language question about security logs by translating
    it to an Elasticsearch query and executing it against the configured
    log backend, e.g. 'show failed logins from IP 203.0.113.45 today'.
    """
    try:
        dsl = nl_to_dsl(question)
    except (json.JSONDecodeError, ValueError) as e:
        return f"Could not translate query to DSL: {e}"

    results = _backend.search(dsl)
    if not results:
        return "No matching events found."
    return json.dumps(results, indent=2, default=str)


if __name__ == "__main__":
    import sys
    q = " ".join(sys.argv[1:]) or "show me failed logins in the last 6 hours"
    print(query_security_logs.invoke({"question": q}))
