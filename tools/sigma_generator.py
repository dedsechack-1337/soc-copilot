"""
Generate Sigma detection rules from a natural-language description of
behavior to detect, using an LLM (Ollama) grounded with a few real Sigma
rules retrieved from the local corpus for style/structure consistency.

Every generated rule is parsed with pySigma before being returned to the
user -- if it fails to parse, we retry once with the error fed back to
the model, then surface the failure rather than silently returning
malformed YAML.
"""
import re
import uuid
from pathlib import Path

import yaml
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

LLM_MODEL = "llama3.1"  # swap for whatever chat model you've pulled in Ollama

SYSTEM_PROMPT = """You are a detection engineer writing Sigma rules.
Output ONLY a single valid Sigma YAML rule -- no markdown fences, no commentary.

Required fields: title, id (a random UUIDv4), status, description, logsource
(product/category/service as appropriate), detection (with a 'selection' block
and a 'condition'), and level (informational|low|medium|high|critical).

Follow standard Sigma field-modifier syntax, e.g. 'CommandLine|contains',
'Image|endswith'. Use realistic Windows Sysmon / Linux auditd / cloud log
field names appropriate to the described behavior.
"""

RETRY_PROMPT_TEMPLATE = """Your previous Sigma rule failed to validate with this error:

{error}

Here is the rule you produced:
{rule}

Fix the YAML so it is valid per the Sigma specification. Output ONLY the
corrected YAML rule, no commentary, no markdown fences.
"""


def _strip_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```(?:yaml|yml)?\n", "", text)
    text = re.sub(r"\n```$", "", text)
    return text.strip()


def _ensure_uuid(rule_yaml: str) -> str:
    """Guarantee a valid UUID4 id field even if the model botches it."""
    data = yaml.safe_load(rule_yaml)
    if not data.get("id") or len(str(data.get("id"))) < 32:
        data["id"] = str(uuid.uuid4())
    return yaml.dump(data, sort_keys=False)


def validate_sigma(rule_yaml: str) -> tuple[bool, str]:
    """Return (is_valid, error_message)."""
    try:
        SigmaRule.from_yaml(rule_yaml)
        return True, ""
    except (SigmaError, yaml.YAMLError) as e:
        return False, str(e)


def generate_sigma_rule(behavior_description: str, llm_model: str = LLM_MODEL) -> dict:
    """
    Generate a Sigma rule for the given behavior description.
    Returns {"yaml": str, "valid": bool, "error": str|None, "attempts": int}
    """
    llm = ChatOllama(model=llm_model, temperature=0.2)

    messages = [
        ("system", SYSTEM_PROMPT),
        ("user", f"Write a Sigma rule to detect: {behavior_description}"),
    ]
    response = llm.invoke(messages)
    rule_yaml = _strip_fences(response.content)

    try:
        rule_yaml = _ensure_uuid(rule_yaml)
    except yaml.YAMLError:
        pass  # will be caught by validation below

    is_valid, error = validate_sigma(rule_yaml)
    attempts = 1

    if not is_valid:
        # One retry, feeding the error back to the model
        retry_msg = RETRY_PROMPT_TEMPLATE.format(error=error, rule=rule_yaml)
        messages.append(("assistant", response.content))
        messages.append(("user", retry_msg))
        response = llm.invoke(messages)
        rule_yaml = _strip_fences(response.content)
        try:
            rule_yaml = _ensure_uuid(rule_yaml)
        except yaml.YAMLError:
            pass
        is_valid, error = validate_sigma(rule_yaml)
        attempts = 2

    return {
        "yaml": rule_yaml,
        "valid": is_valid,
        "error": None if is_valid else error,
        "attempts": attempts,
    }


@tool
def generate_sigma_detection_rule(behavior_description: str) -> str:
    """
    Generate a Sigma detection rule (YAML) for a described malicious or
    suspicious behavior, e.g. 'PowerShell downloading and executing a
    remote script'. The rule is validated against the Sigma spec before
    being returned.
    """
    result = generate_sigma_rule(behavior_description)
    if result["valid"]:
        return f"```yaml\n{result['yaml']}\n```\n\n✅ Valid Sigma rule (pySigma-checked)."
    return (
        f"⚠️ Generated rule failed validation after {result['attempts']} attempt(s): "
        f"{result['error']}\n\n```yaml\n{result['yaml']}\n```"
    )


if __name__ == "__main__":
    import sys
    desc = " ".join(sys.argv[1:]) or "PowerShell process spawned by winword.exe with encoded command"
    out = generate_sigma_rule(desc)
    print(out["yaml"])
    print("VALID:", out["valid"], out["error"])
