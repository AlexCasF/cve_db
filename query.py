import os
import re

import requests
from dotenv import load_dotenv

from db import fetch_all, print_rows


CEREBRAS_URL = "https://api.cerebras.ai/v1/chat/completions"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
ALLOWED_TABLES = {"cves", "vendors", "products", "cve_products"}


def get_clarification(question):
    lower = question.lower()
    if ("bad" in lower or "serious" in lower) and not re.search(r"\b\d+(\.\d+)?\b", lower):
        return "What CVSS score should count as bad?", "9.0"
    if ("recent" in lower or "latest" in lower or "new" in lower) and not re.search(r"\b(last|today|yesterday|\d{4}-\d{2}-\d{2})\b", lower):
        return "What date range should count as recent?", "last 30 days"
    return None


def apply_clarification(question, answer):
    return f"{question}. Additional detail: {answer}."


def clarify(question):
    clarification = get_clarification(question)
    if clarification is None:
        return question

    prompt, default = clarification
    answer = input(f"{prompt} [{default}]: ").strip() or default
    return apply_clarification(question, answer)


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


def run_query(db_path, question):
    sql = validate_sql(extract_sql(generate_sql(clarify(question))))
    return sql, fetch_all(db_path, sql)


def run_query_with_text(db_path, question):
    sql = validate_sql(extract_sql(generate_sql(question)))
    return sql, fetch_all(db_path, sql)


def extract_sql(text):
    match = re.search(r"```(?:sql)?\s*(.*?)```", text, re.IGNORECASE | re.DOTALL)
    if match:
        text = match.group(1)
    match = re.search(r"\bselect\b.*", text, re.IGNORECASE | re.DOTALL)
    if match:
        text = match.group(0)
    return text.strip().rstrip(";")


def validate_sql(sql):
    if not sql.lower().startswith("select"):
        raise ValueError("Only SELECT queries are allowed.")
    if re.search(r"\b(insert|update|delete|drop|alter|create|pragma|attach|vacuum)\b", sql, re.IGNORECASE):
        raise ValueError("Unsafe SQL blocked.")
    for table in re.findall(r"\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_]*)", sql, re.IGNORECASE):
        if table.lower() not in ALLOWED_TABLES:
            raise ValueError(f"Table not allowed: {table}")
    if " limit " not in sql.lower():
        sql = f"{sql} LIMIT 20"
    return sql


def generate_sql_cerebras(question, provider_api_key, provider_model):
    schema = (
        "cves(cve_id, description, published, last_modified, severity, cvss_score, source, url)\n"
        "vendors(vendor_id, name)\n"
        "products(product_id, vendor_id, name)\n"
        "cve_products(cve_id, product_id)"
    )
    response = requests.post(
        CEREBRAS_URL,
        headers={"Authorization": f"Bearer {provider_api_key}", "Content-Type": "application/json"},
        json={
            "model": provider_model,
            "temperature": 0.1,
            "max_tokens": 300,
            "messages": [
                {
                    "role": "system",
                    "content": "Return exactly one SQLite SELECT query. Use only the provided schema and never generate mutating SQL.",
                },
                {"role": "user", "content": f"Schema:\n{schema}\nQuestion: {question}\nSQL:"},
            ],
        },
        timeout=60,
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


def generate_sql_gemini(question, provider_api_key, provider_model):
    schema = (
        "cves(cve_id, description, published, last_modified, severity, cvss_score, source, url)\n"
        "vendors(vendor_id, name)\n"
        "products(product_id, vendor_id, name)\n"
        "cve_products(cve_id, product_id)"
    )
    prompt = (
        "Return exactly one SQLite SELECT query. "
        "Use only the provided schema and never generate mutating SQL.\n\n"
        f"Schema:\n{schema}\nQuestion: {question}\nSQL:"
    )
    response = requests.post(
        GEMINI_URL.format(model=provider_model),
        headers={"x-goog-api-key": provider_api_key, "Content-Type": "application/json"},
        json={
            "contents": [
                {
                    "parts": [
                        {"text": prompt},
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
        raise RuntimeError("No Gemini output returned.")
    parts = candidates[0].get("content", {}).get("parts", [])
    texts = [part.get("text", "") for part in parts if isinstance(part, dict)]
    output = "".join(texts).strip()
    if not output:
        raise RuntimeError("Gemini returned no text output.")
    return output


def generate_sql(question):
    if api_key():
        return generate_sql_cerebras(question, api_key(), model_name())
    if gemini_api_key():
        return generate_sql_gemini(question, gemini_api_key(), gemini_model())
    raise RuntimeError("Set CEREBRAS_API_KEY or GEMINI_API_KEY in .env to use AI query.")


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
