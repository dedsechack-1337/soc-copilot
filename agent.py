"""
SOC Copilot agent: routes analyst chat messages to the right tool --
log querying, Sigma generation, YARA generation, or ATT&CK mapping --
using an Ollama chat model as the reasoning/orchestration layer.

Built on LangChain 1.x's `create_agent` (a langgraph tool-calling loop
under the hood).

Run interactively:
    python agent.py
"""
from langchain.agents import create_agent
from langchain_ollama import ChatOllama

from tools.attack_lookup import mitre_attack_lookup
from tools.log_query import query_security_logs
from tools.sigma_generator import generate_sigma_detection_rule
from tools.yara_generator import generate_yara_detection_rule

LLM_MODEL = "llama3.1"

SYSTEM_PROMPT = """You are a SOC (Security Operations Center) threat hunting
copilot for security analysts. You have four tools:

1. query_security_logs -- for questions about actual log/event data
   (failed logins, process executions, network connections, "have we seen X").
2. generate_sigma_detection_rule -- when the analyst wants a Sigma rule
   for a described behavior.
3. generate_yara_detection_rule -- when the analyst wants a YARA rule for
   a malware family, IOC set, or file-based behavior.
4. mitre_attack_lookup -- when the analyst wants to know which ATT&CK
   technique(s) a behavior maps to.

Pick the tool(s) that match the analyst's intent. If a question needs more
than one (e.g. "find suspicious LSASS access and map it to ATT&CK, then
give me a Sigma rule"), call multiple tools in sequence and combine the
results into one coherent answer. Always be precise and concise -- analysts
are triaging under time pressure. Cite technique IDs and rule validation
status explicitly when relevant.
"""

TOOLS = [
    query_security_logs,
    generate_sigma_detection_rule,
    generate_yara_detection_rule,
    mitre_attack_lookup,
]


def build_agent(llm_model: str = LLM_MODEL):
    llm = ChatOllama(model=llm_model, temperature=0.1)
    return create_agent(model=llm, tools=TOOLS, system_prompt=SYSTEM_PROMPT)


def run_turn(agent, user_input: str, history: list) -> str:
    """Invoke the agent with running message history, return the reply text."""
    messages = history + [{"role": "user", "content": user_input}]
    result = agent.invoke({"messages": messages})
    reply = result["messages"][-1].content
    history.append({"role": "user", "content": user_input})
    history.append({"role": "assistant", "content": reply})
    return reply


def chat_loop():
    agent = build_agent()
    history: list = []
    print("SOC Copilot ready. Type 'exit' to quit.\n")
    while True:
        user_input = input("analyst> ").strip()
        if user_input.lower() in {"exit", "quit"}:
            break
        reply = run_turn(agent, user_input, history)
        print("\n" + reply + "\n")


if __name__ == "__main__":
    chat_loop()
