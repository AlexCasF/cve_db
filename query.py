import json
import os
import re
import sqlite3
from datetime import date, datetime
from functools import lru_cache
from typing import Literal

from cerebras.cloud.sdk import Cerebras
from dotenv import load_dotenv
from google import genai
from google.genai import types as genai_types
from pydantic import BaseModel, ConfigDict, model_validator

from db import fetch_all, print_rows


load_dotenv()

ALLOWED_TABLES = {"cves", "vendors", "products", "cve_products"}
MAX_EVENTS = 20


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["ask_clarification", "run_sql"]
    clarification_question: str | None = None
    sql: str | None = None

    @model_validator(mode="after")
    def validate_shape(self):
        if self.action == "ask_clarification":
            if not (self.clarification_question or "").strip():
                raise ValueError("clarification_question is required for ask_clarification.")
            if self.sql is not None:
                raise ValueError("sql must be null for ask_clarification.")
        if self.action == "run_sql":
            if not (self.sql or "").strip():
                raise ValueError("sql is required for run_sql.")
            if self.clarification_question is not None:
                raise ValueError("clarification_question must be null for run_sql.")
        return self


PLAN_SCHEMA = Plan.model_json_schema()
SYSTEM_PROMPT = (
    "You are an NL-to-SQL planner for SQLite.\n"
    "Return only JSON that matches the provided schema.\n"
    "Rules:\n"
    "- Use only these tables: cves, vendors, products, cve_products.\n"
    "- Never generate INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, PRAGMA, ATTACH, VACUUM, or other mutating SQL.\n"
    "- Ask a clarification question only when the request is genuinely too vague to produce a useful SQL query.\n"
    "- Do not ask a clarification question just because the user said latest, newest, most recent, or last added.\n"
    "- If the user asks for the latest or newest bug, sort by COALESCE(c.published, c.last_modified) DESC and return the single newest relevant row unless the user explicitly asks for more.\n"
    "- For product, project, vendor, or keyword searches, search across cves.cve_id, cves.description, vendors.name, and products.name when relevant.\n"
    "- Use SQLite syntax only.\n"
    "- Prefer short, useful SELECT queries with LIMIT 20 unless the user clearly wants one row or an aggregate.\n"
    f"- Today's date is {date.today().isoformat()}.\n"
    "Schema:\n"
    "cves(cve_id, description, published, last_modified, severity, cvss_score, source, url)\n"
    "vendors(vendor_id, name)\n"
    "products(product_id, vendor_id, name)\n"
    "cve_products(cve_id, product_id)\n"
    "Examples in prose:\n"
    "- 'show me the latest added openclaw bug' should search for openclaw, order newest first, and return one row.\n"
    "- 'show me the bad ones' should ask what CVSS threshold counts as bad.\n"
    "- 'show me Microsoft bugs from last month' should filter Microsoft-related rows and the previous calendar month.\n"
    "- 'what is the average risk score in my database' should return an aggregate query.\n"
)
AI_METRICS = {
    "requests": 0,
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "total_tokens": 0,
    "by_provider": {"cerebras": 0, "gemini": 0},
    "events": [],
}


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


@lru_cache(maxsize=1)
def cerebras_client():
    key = api_key()
    if not key:
        return None
    return Cerebras(
        api_key=key,
        max_retries=0,
        timeout=30.0,
        warm_tcp_connection=False,
    )


@lru_cache(maxsize=1)
def gemini_client():
    key = gemini_api_key()
    if not key:
        return None
    return genai.Client(
        api_key=key,
        http_options=genai_types.HttpOptions(
            retry_options=genai_types.HttpRetryOptions(attempts=1),
        ),
    )


def apply_clarification(question, answer):
    return f"Original request: {question}\nClarification from user: {answer}"


def log_stdout(message):
    print(f"[AI] {message}")


def _read_value(obj, *names):
    if obj is None:
        return None
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        if hasattr(obj, name):
            return getattr(obj, name)
    return None


def _error_status(error):
    return _read_value(error, "status_code", "status")


def _error_note(error):
    parts = [error.__class__.__name__]
    status = _error_status(error)
    if status is not None:
        parts.append(f"status={status}")

    message = _read_value(error, "message")
    if message:
        parts.append(str(message).replace("\n", " "))
    elif str(error):
        parts.append(str(error).replace("\n", " "))

    body = _read_value(error, "body")
    if isinstance(body, dict):
        detail = body.get("message") or body.get("error") or body.get("details")
        if detail:
            parts.append(str(detail).replace("\n", " "))

    return " | ".join(parts)


def _content_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            text = _read_value(item, "text")
            if text:
                parts.append(str(text))
        return "".join(parts).strip()
    return str(content or "").strip()


def record_request(provider, model, usage=None, status="ok", note="", http_status=None):
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
        "http_status": http_status if http_status is not None else "-",
        "prompt_tokens": prompt_tokens if prompt_tokens is not None else "-",
        "completion_tokens": completion_tokens if completion_tokens is not None else "-",
        "total_tokens": total_tokens if total_tokens is not None else "-",
        "note": note,
    }
    AI_METRICS["events"].append(event)
    AI_METRICS["events"] = AI_METRICS["events"][-MAX_EVENTS:]

    log_stdout(
        f"request provider={provider} model={model} status={status} "
        f"http_status={event['http_status']} prompt_tokens={event['prompt_tokens']} "
        f"completion_tokens={event['completion_tokens']} total_tokens={event['total_tokens']} "
        f"note={note or '-'}"
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


def parse_plan(text):
    plan = Plan.model_validate_json(text)
    if plan.action == "ask_clarification":
        return {"action": "ask_clarification", "clarification_question": plan.clarification_question.strip()}
    return {"action": "run_sql", "sql": plan.sql.strip()}


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


def user_prompt(question, retry_message=""):
    retry_block = ""
    if retry_message:
        retry_block = (
            "Previous attempt was invalid. Fix it.\n"
            f"Validation error: {retry_message}\n"
        )
    return f"{retry_block}User request:\n{question}"


def _cerebras_usage(completion):
    usage = _read_value(completion, "usage")
    return {
        "prompt_tokens": _read_value(usage, "prompt_tokens"),
        "completion_tokens": _read_value(usage, "completion_tokens"),
        "total_tokens": _read_value(usage, "total_tokens"),
    }


def _gemini_usage(response):
    usage = _read_value(response, "usage_metadata", "usageMetadata")
    return {
        "prompt_tokens": _read_value(usage, "prompt_token_count", "promptTokenCount"),
        "completion_tokens": _read_value(usage, "candidates_token_count", "candidatesTokenCount"),
        "total_tokens": _read_value(usage, "total_token_count", "totalTokenCount"),
    }


def generate_plan_cerebras(question, retry_message=""):
    client = cerebras_client()
    model = model_name()
    if client is None:
        raise RuntimeError("Cerebras client is not configured.")

    try:
        completion = client.chat.completions.create(
            model=model,
            temperature=0,
            max_completion_tokens=220,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt(question, retry_message)},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "nl_sql_plan",
                    "strict": True,
                    "schema": PLAN_SCHEMA,
                },
            },
        )
        usage = _cerebras_usage(completion)
        content = _content_text(_read_value(completion.choices[0].message, "content"))
        if not content:
            record_request("cerebras", model, usage, status="error", note="no content")
            raise RuntimeError("Cerebras returned no structured content.")
        record_request("cerebras", model, usage, status="ok")
        return content
    except Exception as error:
        record_request(
            "cerebras",
            model,
            status="error",
            note=_error_note(error),
            http_status=_error_status(error),
        )
        raise


def generate_plan_gemini(question, retry_message=""):
    client = gemini_client()
    model = gemini_model()
    if client is None:
        raise RuntimeError("Gemini client is not configured.")

    try:
        response = client.models.generate_content(
            model=model,
            contents=user_prompt(question, retry_message),
            config=genai_types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0,
                max_output_tokens=220,
                response_mime_type="application/json",
                response_json_schema=PLAN_SCHEMA,
            ),
        )
        usage = _gemini_usage(response)
        text = _content_text(_read_value(response, "text"))
        if not text:
            record_request("gemini", model, usage, status="error", note="no text")
            raise RuntimeError("Gemini returned no structured text.")
        record_request("gemini", model, usage, status="ok")
        return text
    except Exception as error:
        record_request(
            "gemini",
            model,
            status="error",
            note=_error_note(error),
            http_status=_error_status(error),
        )
        raise


def generate_plan(question, retry_message=""):
    if api_key():
        return generate_plan_cerebras(question, retry_message)
    if gemini_api_key():
        return generate_plan_gemini(question, retry_message)
    raise RuntimeError("Set CEREBRAS_API_KEY or GEMINI_API_KEY in .env to use AI query.")


def resolve_query(db_path, question, max_attempts=1):
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
