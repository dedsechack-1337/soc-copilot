"""
Streamlit chat UI for the SOC Copilot.

Run:
    streamlit run app.py
"""
import streamlit as st

from agent import build_agent, run_turn

st.set_page_config(page_title="SOC Threat Hunting Copilot", page_icon="🛡️", layout="wide")

st.title("🛡️ AI Threat Hunting Assistant")
st.caption(
    "Query logs in natural language · generate Sigma & YARA rules · map behavior to MITRE ATT&CK — "
    "all running locally via Ollama."
)

with st.sidebar:
    st.header("Example prompts")
    st.markdown(
        "- *Show me failed logins in the last 6 hours*\n"
        "- *What ATT&CK technique covers dumping LSASS memory?*\n"
        "- *Write a Sigma rule for PowerShell downloading a remote script*\n"
        "- *Give me a YARA rule for a Cobalt Strike beacon*\n"
        "- *Find suspicious LSASS access, map it to ATT&CK, and give me a Sigma rule*"
    )
    st.divider()
    if st.button("Clear conversation"):
        st.session_state.clear()
        st.rerun()

if "agent" not in st.session_state:
    with st.spinner("Loading agent..."):
        st.session_state.agent = build_agent()
if "history" not in st.session_state:
    st.session_state.history = []
if "display_messages" not in st.session_state:
    st.session_state.display_messages = []

for msg in st.session_state.display_messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

user_input = st.chat_input("Ask about logs, request a Sigma/YARA rule, or map a behavior to ATT&CK...")

if user_input:
    st.session_state.display_messages.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)

    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            try:
                reply = run_turn(st.session_state.agent, user_input, st.session_state.history)
            except Exception as e:
                reply = (
                    f"⚠️ Error reaching the local model: `{e}`\n\n"
                    "Make sure Ollama is running (`ollama serve`) and the required "
                    "models are pulled (see README)."
                )
        st.markdown(reply)
    st.session_state.display_messages.append({"role": "assistant", "content": reply})
