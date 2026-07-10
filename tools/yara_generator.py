"""
Generate YARA rules from a natural-language description (malware family,
IOC set, behavior) or from provided string/hex indicators, using an LLM
(Ollama). Every rule is compiled with yara-python before being returned;
on a compile error we retry once with the error fed back to the model.
"""
import re

import yara
from langchain_core.tools import tool
from langchain_ollama import ChatOllama

LLM_MODEL = "llama3.1"

SYSTEM_PROMPT = """You are a malware analyst writing YARA rules.
Output ONLY a single valid YARA rule -- no markdown fences, no commentary.

Rules must:
- have a clear, descriptive, CamelCase or snake_case identifier
- include a meta block with description and author = "SOC Copilot"
- include a strings block with at least 2-4 distinguishing strings/hex
  patterns/regexes relevant to the description (avoid overly generic
  strings that would cause false positives, e.g. single common API names
  alone)
- include a condition block combining the strings sensibly (not just
  "any of them" for everything -- use boolean logic that reflects real
  detection intent)
- be syntactically valid per the YARA specification (this will be
  compiled with yara-python and rejected if invalid)
"""

RETRY_PROMPT_TEMPLATE = """Your previous YARA rule failed to compile with this error:

{error}

Here is the rule you produced:
{rule}

Fix the syntax so it compiles cleanly with yara-python. Output ONLY the
corrected rule, no commentary, no markdown fences.
"""


def _strip_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```(?:yara|yar)?\n", "", text)
    text = re.sub(r"\n```$", "", text)
    return text.strip()


def validate_yara(rule_text: str) -> tuple[bool, str]:
    try:
        yara.compile(source=rule_text)
        return True, ""
    except yara.Error as e:
        return False, str(e)


def generate_yara_rule(description: str, llm_model: str = LLM_MODEL) -> dict:
    """
    Generate a YARA rule for the given description (malware family,
    behavior, or IOC list).
    Returns {"rule": str, "valid": bool, "error": str|None, "attempts": int}
    """
    llm = ChatOllama(model=llm_model, temperature=0.2)

    messages = [
        ("system", SYSTEM_PROMPT),
        ("user", f"Write a YARA rule to detect: {description}"),
    ]
    response = llm.invoke(messages)
    rule_text = _strip_fences(response.content)

    is_valid, error = validate_yara(rule_text)
    attempts = 1

    if not is_valid:
        retry_msg = RETRY_PROMPT_TEMPLATE.format(error=error, rule=rule_text)
        messages.append(("assistant", response.content))
        messages.append(("user", retry_msg))
        response = llm.invoke(messages)
        rule_text = _strip_fences(response.content)
        is_valid, error = validate_yara(rule_text)
        attempts = 2

    return {
        "rule": rule_text,
        "valid": is_valid,
        "error": None if is_valid else error,
        "attempts": attempts,
    }


@tool
def generate_yara_detection_rule(description: str) -> str:
    """
    Generate a YARA rule for a described malware family, behavior, or set
    of IOCs, e.g. 'Cobalt Strike beacon with default sleep/jitter config'.
    The rule is compiled with yara-python to confirm syntax validity
    before being returned.
    """
    result = generate_yara_rule(description)
    if result["valid"]:
        return f"```yara\n{result['rule']}\n```\n\n✅ Compiles cleanly (yara-python-checked)."
    return (
        f"⚠️ Generated rule failed to compile after {result['attempts']} attempt(s): "
        f"{result['error']}\n\n```yara\n{result['rule']}\n```"
    )


if __name__ == "__main__":
    import sys
    desc = " ".join(sys.argv[1:]) or "Cobalt Strike default beacon config strings"
    out = generate_yara_rule(desc)
    print(out["rule"])
    print("VALID:", out["valid"], out["error"])
