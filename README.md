# AI Threat Hunting Assistant (SOC Copilot)

A local-first AI copilot for security analysts: query logs in natural
language, generate validated Sigma and YARA rules, and map behaviors to
MITRE ATT&CK — all through a chat interface, powered by an open LLM via
Ollama with retrieval-augmented generation over the real ATT&CK corpus.

## Architecture

```
                        ┌───────────────────┐
                        │   Streamlit Chat    │
                        └─────────┬───────────┘
                                  │
                        ┌─────────▼───────────┐
                        │  LangChain Agent      │  (agent.py — create_agent,
                        │  (Ollama chat model)   │   langgraph tool-calling loop)
                        └──┬───────┬───────┬────┘
              ┌────────────┘       │       └────────────┐
              ▼                    ▼                    ▼
    ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
    │ query_security_   │ │ generate_sigma_    │ │ generate_yara_    │
    │ logs               │ │ detection_rule      │ │ detection_rule     │
    │ (NL → ES DSL)       │ │ (LLM + pySigma      │ │ (LLM + yara-python  │
    │                     │ │  validation)         │ │  compilation check)  │
    └──────────────────┘ └──────────────────┘ └──────────────────┘
              │
              ▼
    ┌──────────────────┐
    │ mitre_attack_      │
    │ lookup              │
    │ (ChromaDB RAG over   │
    │  real ATT&CK STIX)    │
    └──────────────────┘
```

## What's real vs. what you need to plug in

| Component | Status |
|---|---|
| MITRE ATT&CK data | **Real** — pulled live from `mitre/cti` GitHub repo, 697 techniques/sub-techniques parsed |
| ATT&CK vector search | **Real** — ChromaDB + Ollama embeddings, tested end-to-end logic |
| Sigma generation + validation | **Real** — pySigma parses/validates every generated rule; auto-retries on failure |
| YARA generation + validation | **Real** — yara-python compiles every generated rule; auto-retries on failure |
| Log querying | **Mock backend included** — swap `MockLogBackend` for `ElasticsearchBackend` (stub provided in `tools/log_query.py`) pointed at your real SIEM index |
| LLM | Requires **Ollama** running locally with a chat model (`llama3.1` by default) and an embedding model (`nomic-embed-text`) |

## Setup

### 1. Install Ollama and pull models
```bash
# https://ollama.com/download
ollama pull llama3.1          # chat/reasoning model
ollama pull nomic-embed-text  # embedding model for ATT&CK RAG
ollama serve                  # if not already running as a service
```

### 2. Install Python dependencies
```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### 3. Build the ATT&CK knowledge base (one-time)
```bash
# Fetch + parse the latest MITRE ATT&CK Enterprise matrix
curl -o data/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
python ingest/parse_attack.py          # -> data/techniques.json
python ingest/build_vectorstore.py     # -> vectorstore/attack_chroma/
```

### 4. Run it

**Chat UI:**
```bash
streamlit run app.py
```

**CLI:**
```bash
python agent.py
```

**Individual tools (for testing):**
```bash
python tools/attack_lookup.py "dumping lsass memory to steal credentials"
python tools/sigma_generator.py "PowerShell downloading and executing a remote script"
python tools/yara_generator.py "Cobalt Strike beacon default config"
python tools/log_query.py "show failed logins in the last 6 hours"
```

## Connecting a real SIEM

Edit `tools/log_query.py`:
```python
from tools.log_query import ElasticsearchBackend
_backend = ElasticsearchBackend(hosts=["https://your-es-host:9200"], index_pattern="security-logs-*")
```
Update `SCHEMA_DESCRIPTION` in the same file to match your actual index
field mappings — the quality of NL→DSL translation depends entirely on
the LLM having an accurate schema to work from. For Splunk, write an
equivalent `SplunkBackend` that translates to SPL instead of ES DSL (the
NL2DSL prompt template is a good starting point to adapt).

## Design notes

- **Validation-first rule generation**: LLMs reliably produce *plausible-looking*
  but subtly broken Sigma/YARA syntax (bad UUIDs, missing `condition` blocks,
  unbalanced YARA string references). Both generators parse/compile the
  output before returning it, and auto-retry once with the error fed back
  to the model. If it still fails, the analyst sees the raw output *and*
  the validation error, rather than a silently broken rule.
- **RAG for ATT&CK, not for querying every rule generation**: the ATT&CK
  mapping is pure retrieval (fast, deterministic, no hallucination risk).
  Sigma/YARA generation currently doesn't retrieve example rules for
  style grounding — a good next step (see below) is embedding a corpus of
  real Sigma/YARA rules (e.g. SigmaHQ's ruleset) the same way ATT&CK is
  embedded, and retrieving similar examples to steer the LLM's style and
  reduce validation failures further.
- **Local-first**: everything runs through Ollama, so log data and
  generated detections never leave your infrastructure.

## Next steps / extension ideas
- Embed the [SigmaHQ ruleset](https://github.com/SigmaHQ/sigma) and a YARA
  rule corpus into their own Chroma collections for few-shot retrieval.
- Add a `sigma-cli`/pySigma backend conversion step so generated rules can
  be immediately converted to your SIEM's native query language.
- Add conversation memory persistence (SQLite-backed langgraph checkpointer)
  so analysts can resume investigations across sessions.
- Add a feedback loop: let analysts thumbs-up/down generated rules, and
  feed accepted rules back into the retrieval corpus over time.
