import json
import os
import re
import sqlite3
from datetime import date

import requests
from dotenv import load_dotenv

from db import fetch_all, print_rows


CEREBRAS_URL = "https://api.cerebras.ai/v1/chat/completions"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
ALLOWED_TABLES = {"cves", "vendors", "products", "cve_products"}


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
    choices = payload.get("choices", [])
    if not choices:
        raise RuntimeError(f"Cerebras returned no choices: {payload}")
    message = choices[0].get("message", {})
    content = message.get("content")
    if isinstance(content, str) and content.strip():
        return content
    if isinstance(content, list):
        texts = [item.get("text", "") for item in content if isinstance(item, dict)]
        merged = "".join(texts).strip()
        if merged:
            return merged
    raise RuntimeError(f"Cerebras returned no usable message content: {payload}")


def generate_plan_gemini(question, provider_api_key, provider_model, retry_message=""):
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
    candidates = payload.get("candidates", [])
    if not candidates:
        raise RuntimeError(f"No Gemini output returned: {payload}")
    candidate = candidates[0]
    parts = candidate.get("content", {}).get("parts", [])
    texts = [part.get("text", "") for part in parts if isinstance(part, dict)]
    output = "".join(texts).strip()
    if output:
        return output
    finish_reason = candidate.get("finishReason", "unknown")
    raise RuntimeError(f"Gemini returned no text output. Finish reason: {finish_reason}. Payload: {payload}")


def generate_plan(question, retry_message=""):
    if api_key():
        return generate_plan_cerebras(question, api_key(), model_name(), retry_message)
    if gemini_api_key():
        return generate_plan_gemini(question, gemini_api_key(), gemini_model(), retry_message)
    raise RuntimeError("Set CEREBRAS_API_KEY or GEMINI_API_KEY in .env to use AI query.")


def resolve_query(db_path, question, max_attempts=3):
    retry_message = ""
    last_error = None

    for _ in range(max_attempts):
        raw = generate_plan(question, retry_message)
        try:
            plan = parse_plan(raw)
            if plan["action"] == "ask_clarification":
                return plan

            sql = validate_sql(plan["sql"])
            validate_sql_with_sqlite(db_path, sql)
            rows = fetch_all(db_path, sql)
            return {"action": "run_sql", "sql": sql, "rows": rows}
        except Exception as error:
            last_error = error
            retry_message = str(error)

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
