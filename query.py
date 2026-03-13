import json
import os
import re
import sqlite3
from datetime import date, datetime

import requests
from dotenv import load_dotenv

from db import fetch_all, print_rows


CEREBRAS_URL = "https://api.cerebras.ai/v1/chat/completions"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
ALLOWED_TABLES = {"cves", "vendors", "products", "cve_products"}
MAX_EVENTS = 20
AI_METRICS = {
    "requests": 0,
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "total_tokens": 0,
    "by_provider": {"cerebras": 0, "gemini": 0},
    "events": [],
}


def log_stdout(message):
    print(f"[AI] {message}")


def record_request(provider, model, usage=None, status="ok", note=""):
    usage = usage or {}
    prompt_tokens = usage.get("prompt_tokens")
    completion_tokens = usage.get("completion_tokens")
    total_tokens = usage.get("total_tokens")

    AI_METRICS["requests"] += 1
    AI_METRICS["by_provider"][provider] = AI_METRICS["by_provider"].get(provider, 0) + 1
    if isinstance(prompt_tokens, int):
        AI_METRICS["prompt_tokens"] += prompt_tokens
    if isinstance(completion_tokens, int):
        AI_METRICS["completion_tokens"] += completion_tokens
    if isinstance(total_tokens, int):
        AI_METRICS["total_tokens"] += total_tokens

    event = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "provider": provider,
        "model": model,
        "status": status,
        "prompt_tokens": prompt_tokens if prompt_tokens is not None else "-",
        "completion_tokens": completion_tokens if completion_tokens is not None else "-",
        "total_tokens": total_tokens if total_tokens is not None else "-",
        "note": note,
    }
    AI_METRICS["events"].append(event)
    AI_METRICS["events"] = AI_METRICS["events"][-MAX_EVENTS:]

    log_stdout(
        f"request provider={provider} model={model} status={status} "
        f"prompt_tokens={event['prompt_tokens']} completion_tokens={event['completion_tokens']} "
        f"total_tokens={event['total_tokens']} note={note or '-'}"
    )


def get_metrics():
    return {
        "requests": AI_METRICS["requests"],
        "prompt_tokens": AI_METRICS["prompt_tokens"],
        "completion_tokens": AI_METRICS["completion_tokens"],
        "total_tokens": AI_METRICS["total_tokens"],
        "by_provider": dict(AI_METRICS["by_provider"]),
        "events": list(AI_METRICS["events"]),
    }


def reset_metrics():
    AI_METRICS["requests"] = 0
    AI_METRICS["prompt_tokens"] = 0
    AI_METRICS["completion_tokens"] = 0
    AI_METRICS["total_tokens"] = 0
    AI_METRICS["by_provider"] = {"cerebras": 0, "gemini": 0}
    AI_METRICS["events"] = []


def model_name():
    load_dotenv()
    return os.getenv("CEREBRAS_MODEL", "gpt-oss-120b")


def api_key():
    load_dotenv()
    return os.getenv("CEREBRAS_API_KEY", "")


def gemini_model():
    load_dotenv()
    return os.getenv("GEMINI_MODEL", "gemini-2.5-flash")


def gemini_api_key():
    load_dotenv()
    return os.getenv("GEMINI_API_KEY", "")


def apply_clarification(question, answer):
    return f"Original request: {question}\nClarification from user: {answer}"


def extract_json(text):
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.IGNORECASE | re.DOTALL)
    if fenced:
        return fenced.group(1).strip()

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError(f"Model did not return JSON: {text}")
    return text[start : end + 1]


def parse_plan(text):
    payload = json.loads(extract_json(text))
    action = payload.get("action")
    if action == "ask_clarification":
        question = str(payload.get("clarification_question", "")).strip()
        if not question:
            raise ValueError("Missing clarification_question in model response.")
        return {"action": "ask_clarification", "clarification_question": question}
    if action == "run_sql":
        sql = str(payload.get("sql", "")).strip()
        if not sql:
            raise ValueError("Missing sql in model response.")
        return {"action": "run_sql", "sql": sql}
    raise ValueError(f"Unsupported action in model response: {payload}")


def extract_sql(text):
    match = re.search(r"```(?:sql)?\s*(.*?)```", text, re.IGNORECASE | re.DOTALL)
    if match:
        text = match.group(1)
    match = re.search(r"\bselect\b.*", text, re.IGNORECASE | re.DOTALL)
    if match:
        text = match.group(0)
    return text.strip().rstrip(";")


def validate_sql(sql):
    cleaned = extract_sql(sql)
    if not cleaned.lower().startswith("select"):
        raise ValueError("Only SELECT queries are allowed.")
    if re.search(r"\b(insert|update|delete|drop|alter|create|pragma|attach|vacuum|replace|truncate)\b", cleaned, re.IGNORECASE):
        raise ValueError("Unsafe SQL blocked.")
    for table in re.findall(r"\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_]*)", cleaned, re.IGNORECASE):
        if table.lower() not in ALLOWED_TABLES:
            raise ValueError(f"Table not allowed: {table}")
    if " limit " not in cleaned.lower():
        cleaned = f"{cleaned} LIMIT 20"
    return cleaned


def validate_sql_with_sqlite(db_path, sql):
    with sqlite3.connect(db_path) as connection:
        connection.execute(f"EXPLAIN QUERY PLAN {sql}")


def system_prompt(retry_message=""):
    examples = """
Example 1
User: show me the latest added openclaw bug
Assistant:
{
  "action": "run_sql",
  "sql": "SELECT c.cve_id, c.description, c.published, c.last_modified, c.severity, c.cvss_score, c.source, c.url FROM cves c LEFT JOIN cve_products cp ON cp.cve_id = c.cve_id LEFT JOIN products p ON p.product_id = cp.product_id LEFT JOIN vendors v ON v.vendor_id = p.vendor_id WHERE LOWER(c.cve_id) LIKE '%openclaw%' OR LOWER(c.description) LIKE '%openclaw%' OR LOWER(v.name) LIKE '%openclaw%' OR LOWER(p.name) LIKE '%openclaw%' GROUP BY c.cve_id ORDER BY COALESCE(c.published, c.last_modified) DESC, c.last_modified DESC LIMIT 1"
}

Example 2
User: show me the bad ones
Assistant:
{
  "action": "ask_clarification",
  "clarification_question": "What CVSS score should count as bad?"
}

Example 3
User: show me Microsoft bugs from last month
Assistant:
{
  "action": "run_sql",
  "sql": "SELECT DISTINCT c.cve_id, c.description, c.published, c.severity, c.cvss_score FROM cves c LEFT JOIN cve_products cp ON cp.cve_id = c.cve_id LEFT JOIN products p ON p.product_id = cp.product_id LEFT JOIN vendors v ON v.vendor_id = p.vendor_id WHERE LOWER(v.name) LIKE '%microsoft%' AND date(substr(c.published, 1, 10)) >= date('now', 'start of month', '-1 month') AND date(substr(c.published, 1, 10)) < date('now', 'start of month') ORDER BY c.published DESC"
}

Example 4
User: what is the average risk score in my database
Assistant:
{
  "action": "run_sql",
  "sql": "SELECT ROUND(AVG(cvss_score), 2) AS average_cvss_score FROM cves"
}
""".strip()

    retry_block = ""
    if retry_message:
        retry_block = f"\nPrevious attempt was invalid. Fix it.\nValidation error: {retry_message}\n"

    return (
        "You are an NL-to-SQL planner for SQLite.\n"
        "You must return JSON only.\n"
        "Valid response shapes:\n"
        '1. {"action":"ask_clarification","clarification_question":"..."}\n'
        '2. {"action":"run_sql","sql":"SELECT ..."}\n'
        "Rules:\n"
        "- Use only these tables: cves, vendors, products, cve_products.\n"
        "- Never generate INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, PRAGMA, ATTACH, VACUUM, or other mutating SQL.\n"
        "- If the user asks for the latest, newest, most recent, or last added item, sort descending by COALESCE(c.published, c.last_modified) and return only the newest relevant row unless the user explicitly asks for multiple rows.\n"
        "- For topic words such as vendor, product, or project names, search across cves.cve_id, cves.description, vendors.name, and products.name when relevant.\n"
        "- Ask a clarification question only when the request is genuinely ambiguous and a reasonable SQL query cannot be formed.\n"
        "- Do not ask a clarification question just because the user said latest or newest.\n"
        "- Prefer concise, useful SELECT queries.\n"
        f"- Today's date is {date.today().isoformat()}.\n"
        "Schema:\n"
        "cves(cve_id, description, published, last_modified, severity, cvss_score, source, url)\n"
        "vendors(vendor_id, name)\n"
        "products(product_id, vendor_id, name)\n"
        "cve_products(cve_id, product_id)\n"
        f"{retry_block}\n"
        f"{examples}\n"
    )


def generate_plan_cerebras(question, provider_api_key, provider_model, retry_message=""):
    try:
        response = requests.post(
            CEREBRAS_URL,
            headers={"Authorization": f"Bearer {provider_api_key}", "Content-Type": "application/json"},
            json={
                "model": provider_model,
                "temperature": 0.1,
                "max_tokens": 500,
                "messages": [
                    {"role": "system", "content": system_prompt(retry_message)},
                    {"role": "user", "content": question},
                ],
            },
            timeout=60,
        )
        response.raise_for_status()
        payload = response.json()
        usage_raw = payload.get("usage", {})
        usage = {
            "prompt_tokens": usage_raw.get("prompt_tokens"),
            "completion_tokens": usage_raw.get("completion_tokens"),
            "total_tokens": usage_raw.get("total_tokens"),
        }
        choices = payload.get("choices", [])
        if not choices:
            record_request("cerebras", provider_model, usage, status="error", note="no choices")
            raise RuntimeError(f"Cerebras returned no choices: {payload}")
        message = choices[0].get("message", {})
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            record_request("cerebras", provider_model, usage, status="ok")
            return content
        if isinstance(content, list):
            texts = [item.get("text", "") for item in content if isinstance(item, dict)]
            merged = "".join(texts).strip()
            if merged:
                record_request("cerebras", provider_model, usage, status="ok")
                return merged
        record_request("cerebras", provider_model, usage, status="error", note="no usable content")
        raise RuntimeError(f"Cerebras returned no usable message content: {payload}")
    except Exception as error:
        if "payload" not in locals():
            record_request("cerebras", provider_model, status="error", note=str(error))
        raise


def generate_plan_gemini(question, provider_api_key, provider_model, retry_message=""):
    try:
        response = requests.post(
            GEMINI_URL.format(model=provider_model),
            headers={"x-goog-api-key": provider_api_key, "Content-Type": "application/json"},
            json={
                "contents": [
                    {
                        "parts": [
                            {"text": system_prompt(retry_message)},
                            {"text": f"User request:\n{question}"},
                        ]
                    }
                ]
            },
            timeout=60,
        )
        response.raise_for_status()
        payload = response.json()
        usage_raw = payload.get("usageMetadata", {})
        usage = {
            "prompt_tokens": usage_raw.get("promptTokenCount"),
            "completion_tokens": usage_raw.get("candidatesTokenCount"),
            "total_tokens": usage_raw.get("totalTokenCount"),
        }
        candidates = payload.get("candidates", [])
        if not candidates:
            record_request("gemini", provider_model, usage, status="error", note="no candidates")
            raise RuntimeError(f"No Gemini output returned: {payload}")
        candidate = candidates[0]
        parts = candidate.get("content", {}).get("parts", [])
        texts = [part.get("text", "") for part in parts if isinstance(part, dict)]
        output = "".join(texts).strip()
        if output:
            record_request("gemini", provider_model, usage, status="ok")
            return output
        finish_reason = candidate.get("finishReason", "unknown")
        record_request("gemini", provider_model, usage, status="error", note=f"no text: {finish_reason}")
        raise RuntimeError(f"Gemini returned no text output. Finish reason: {finish_reason}. Payload: {payload}")
    except Exception as error:
        if "payload" not in locals():
            record_request("gemini", provider_model, status="error", note=str(error))
        raise


def generate_plan(question, retry_message=""):
    if api_key():
        return generate_plan_cerebras(question, api_key(), model_name(), retry_message)
    if gemini_api_key():
        return generate_plan_gemini(question, gemini_api_key(), gemini_model(), retry_message)
    raise RuntimeError("Set CEREBRAS_API_KEY or GEMINI_API_KEY in .env to use AI query.")


def resolve_query(db_path, question, max_attempts=3):
    retry_message = ""
    last_error = None

    for attempt in range(1, max_attempts + 1):
        log_stdout(f"resolve attempt={attempt}/{max_attempts} question={question!r}")
        raw = generate_plan(question, retry_message)
        try:
            plan = parse_plan(raw)
            if plan["action"] == "ask_clarification":
                log_stdout(f"planner requested clarification question={plan['clarification_question']!r}")
                return plan

            sql = validate_sql(plan["sql"])
            validate_sql_with_sqlite(db_path, sql)
            rows = fetch_all(db_path, sql)
            log_stdout(f"sql accepted rows={len(rows)}")
            return {"action": "run_sql", "sql": sql, "rows": rows}
        except Exception as error:
            last_error = error
            retry_message = str(error)
            log_stdout(f"attempt failed reason={retry_message}")

    raise RuntimeError(f"Could not produce a valid AI query. Last error: {last_error}")


def run_query(db_path, question):
    current_question = question
    for _ in range(3):
        result = resolve_query(db_path, current_question)
        if result["action"] == "run_sql":
            return result["sql"], result["rows"]
        answer = input(f"{result['clarification_question']} ").strip()
        current_question = apply_clarification(current_question, answer)
    raise RuntimeError("Too many clarification turns.")


def run_query_with_text(db_path, question):
    result = resolve_query(db_path, question)
    if result["action"] != "run_sql":
        raise RuntimeError(result["clarification_question"])
    return result["sql"], result["rows"]


def run(db_path):
    print("\nAI query")
    question = input("Ask a question: ").strip()
    if not question:
        print("Question is required.")
        return

    if not api_key() and not gemini_api_key():
        print("Set CEREBRAS_API_KEY or GEMINI_API_KEY in .env.")
        return

    try:
        sql, rows = run_query(db_path, question)
    except Exception as error:
        print(f"AI query failed: {error}")
        return

    print("\nGenerated SQL")
    print(sql)
    print("\nResults")
    print_rows(rows, limit=20)
