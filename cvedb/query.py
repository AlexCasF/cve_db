import os
import re

import requests

from cvedb.db import fetch_all, print_rows


CEREBRAS_URL = "https://api.cerebras.ai/v1/chat/completions"
ALLOWED_TABLES = {"cves", "vendors", "products", "cve_products"}


def clarify(question):
    lower = question.lower()
    if ("bad" in lower or "serious" in lower) and not re.search(r"\b\d+(\.\d+)?\b", lower):
        threshold = input("What CVSS score should count as bad? [9.0]: ").strip() or "9.0"
        return f"{question}. Treat bad as CVSS >= {threshold}."
    if ("recent" in lower or "latest" in lower or "new" in lower) and not re.search(r"\b(last|today|yesterday|\d{4}-\d{2}-\d{2})\b", lower):
        window = input("What date range should count as recent? [last 30 days]: ").strip() or "last 30 days"
        return f"{question}. Treat recent as {window}."
    return question


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


def generate_sql(question, api_key, model):
    schema = (
        "cves(cve_id, description, published, last_modified, severity, cvss_score, source, url)\n"
        "vendors(vendor_id, name)\n"
        "products(product_id, vendor_id, name)\n"
        "cve_products(cve_id, product_id)"
    )
    response = requests.post(
        CEREBRAS_URL,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json={
            "model": model,
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


def run(db_path):
    print("\nAI query")
    question = input("Ask a question: ").strip()
    if not question:
        print("Question is required.")
        return

    api_key = os.getenv("CEREBRAS_API_KEY") or input("Cerebras API key: ").strip()
    if not api_key:
        print("API key is required.")
        return

    try:
        sql = validate_sql(extract_sql(generate_sql(clarify(question), api_key, os.getenv("CEREBRAS_MODEL", "llama-4-scout-17b-16e-instruct"))))
        rows = fetch_all(db_path, sql)
    except Exception as error:
        print(f"AI query failed: {error}")
        return

    print("\nGenerated SQL")
    print(sql)
    print("\nResults")
    print_rows(rows, limit=20)
