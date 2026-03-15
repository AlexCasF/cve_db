import json
import os
import re
import sqlite3
import time
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
PROVIDER_MIN_INTERVAL = {
    "cerebras": 2.1,
    "gemini": 0.3,
}
LAST_REQUEST_AT = {
    "cerebras": 0.0,
    "gemini": 0.0,
}


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
    "Plan SQLite queries for a CVE database and return JSON matching the provided schema.\n"
    "Tables: cves(cve_id, description, published, last_modified, severity, cvss_score, source, url), "
    "vendors(vendor_id, name), products(product_id, vendor_id, name), cve_products(cve_id, product_id).\n"
    f"Today is {date.today().isoformat()}.\n"
    "Core rules:\n"
    "- Generate SELECT queries only.\n"
    "- Use only cves, vendors, products, cve_products.\n"
    "- Use SQLite syntax.\n"
    "- Ask one clarification question whenever an important part of the request is ambiguous and different interpretations would materially change the results.\n"
    "- Do not invent missing filters such as time ranges, score thresholds, ranking metrics, vendors, products, or counts.\n"
    "- latest/newest/last added means order by COALESCE(c.published, c.last_modified) DESC.\n"
    "- If the user asks for a single bug, return one row with LIMIT 1.\n"
    "- If the user asks for multiple results, use the requested count; otherwise use LIMIT 20 by default.\n"
    "- When joining through cve_products/products/vendors to list CVEs, prefer SELECT DISTINCT to avoid duplicates.\n"
    "Clarification rules:\n"
    "- If the user says recent/current/lately/newly/recently and does not define a time window, ask what time range they mean.\n"
    "- latest/newest/last added are sorting requests and usually do not require clarification by themselves.\n"
    "- If the user uses subjective labels such as bad, worst, serious, important, risky, most vulnerable, or patch first, ask which metric should drive the query.\n"
    "- If a term could plausibly refer to multiple different targets and those targets would produce materially different result sets, ask which one they mean.\n"
    "- Terms that are both product names and common words, or that could refer to a vendor family versus a specific product, should lean toward clarification.\n"
    "Name matching rules:\n"
    "- Vendor and product names in this database are often normalized lowercase.\n"
    "- For vendor/product/company/product-name text matching, prefer case-insensitive matching such as LOWER(v.name) LIKE '%term%' or LOWER(p.name) LIKE '%term%'.\n"
    "- Do not rely on case-sensitive equality for names unless the user clearly provides an exact canonical database value.\n"
    "- If the user gives a company or vendor name such as 'microsoft', first try matching vendors.name.\n"
    "- If the user gives a product/platform/ecosystem term such as 'linux' or 'windows', broad matching across cves.cve_id, cves.description, vendors.name, and products.name is often reasonable.\n"
    "- If the term is materially ambiguous, prefer clarification over a broad catch-all query.\n"
    "- Examples of terms that often need clarification: office, exchange, teams, edge, apache, android, and phrases like 'most vulnerable company'.\n"
    "Query broadening rules:\n"
    "- Avoid overly narrow exact-name filters when a fuzzy match would be safer.\n"
    "- If a first-pass interpretation would likely be brittle but still points to the same target, prefer the broader robust version.\n"
    "- Do not use broad matching as a substitute for clarification when the target itself is uncertain.\n"
    "- For company/vendor searches that might miss due to normalization, prefer LOWER(name) LIKE over exact equality.\n"
    "- For general keyword searches, a robust pattern is OR matching across c.cve_id, c.description, v.name, and p.name.\n"
    "Examples:\n"
    "- 'show me the latest openclaw bug': search broadly enough to find openclaw, order newest first, return one row.\n"
    "- 'show me the latest linux bug': use broad keyword matching across CVE ID, description, vendor, and product, order newest first, return one row.\n"
    "- 'show me the latest 20 microsoft issues': treat microsoft as a vendor/company term, use case-insensitive vendor matching, order newest first, and return 20 CVEs.\n"
    "- 'show me microsoft issues above 8.0': filter Microsoft-related CVEs and apply the score threshold.\n"
    "- 'show me recent microsoft vulnerabilities': ask what time range counts as recent.\n"
    "- 'show me the latest office issues': ask whether the user means Microsoft Office specifically or office software more broadly.\n"
    "- 'which company is the most vulnerable': ask whether this means most CVEs, highest average CVSS, or most critical issues.\n"
    "- 'show me the bad ones': ask what CVSS threshold counts as bad.\n"
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
    return os.getenv("CEREBRAS_MODEL", "qwen-3-235b-a22b-instruct-2507")


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


def preferred_provider():
    if api_key():
        return "cerebras"
    if gemini_api_key():
        return "gemini"
    return None


def available_providers():
    providers = []
    if api_key():
        providers.append("cerebras")
    if gemini_api_key():
        providers.append("gemini")
    return providers


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


def _error_message(error):
    message = _read_value(error, "message")
    if message:
        return str(message)

    body = _read_value(error, "body")
    if isinstance(body, dict):
        detail = body.get("message") or body.get("error") or body.get("details")
        if detail:
            return str(detail)

    return str(error)


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


def _safe_len(value):
    if value is None:
        return 0
    return len(str(value))


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


def throttle_provider(provider, status_callback=None):
    minimum_interval = PROVIDER_MIN_INTERVAL.get(provider, 0)
    if minimum_interval <= 0:
        return

    now = time.monotonic()
    elapsed = now - LAST_REQUEST_AT.get(provider, 0.0)
    wait_seconds = minimum_interval - elapsed
    if wait_seconds > 0:
        log_stdout(f"throttle provider={provider} sleep_seconds={wait_seconds:.2f}")
        notify_status(status_callback, f"Waiting {wait_seconds:.1f}s to respect {provider} rate limits...")
        time.sleep(wait_seconds)
        now = time.monotonic()
    LAST_REQUEST_AT[provider] = now


def notify_status(status_callback, message):
    if status_callback is not None:
        status_callback(message)


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


def sanitize_json_schema(value):
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if key in {"additionalProperties", "default", "title"}:
                continue
            cleaned[key] = sanitize_json_schema(item)
        return cleaned
    if isinstance(value, list):
        return [sanitize_json_schema(item) for item in value]
    return value


def extract_json(text):
    text = str(text or "").strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.IGNORECASE | re.DOTALL)
    if fenced:
        return fenced.group(1).strip()

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return text
    return text[start : end + 1].strip()


def parse_plan(text):
    plan = Plan.model_validate_json(extract_json(text))
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
    if not re.search(r"\blimit\b", cleaned, re.IGNORECASE):
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


def _is_unsupported_reasoning_error(error):
    if _error_status(error) != 422:
        return False
    message = _error_message(error).lower()
    return "reasoning effort is not supported" in message


def generate_plan_cerebras(question, retry_message="", status_callback=None):
    client = cerebras_client()
    model = model_name()
    if client is None:
        raise RuntimeError("Cerebras client is not configured.")

    try:
        notify_status(status_callback, "Thinking through the request...")
        throttle_provider("cerebras", status_callback=status_callback)
        notify_status(status_callback, "Drafting a SQL plan...")
        request_kwargs = {
            "model": model,
            "temperature": 0,
            "max_completion_tokens": 384,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt(question, retry_message)},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "nl_sql_plan",
                    "strict": True,
                    "schema": PLAN_SCHEMA,
                },
            },
        }
        try:
            completion = client.chat.completions.create(
                reasoning_effort="low",
                reasoning_format="hidden",
                **request_kwargs,
            )
        except Exception as error:
            if not _is_unsupported_reasoning_error(error):
                raise
            log_stdout(f"retry provider=cerebras model={model} without_reasoning_params=true")
            notify_status(status_callback, "Retrying without model-specific reasoning settings...")
            completion = client.chat.completions.create(**request_kwargs)
        choice = completion.choices[0]
        message = choice.message
        usage = _cerebras_usage(completion)
        content = _content_text(_read_value(message, "content"))
        finish_reason = _read_value(choice, "finish_reason")
        reasoning = _read_value(message, "reasoning")
        if not content:
            note = (
                f"no content; finish_reason={finish_reason or '-'}; "
                f"reasoning_chars={_safe_len(reasoning)}"
            )
            record_request("cerebras", model, usage, status="error", note=note)
            raise RuntimeError(f"Cerebras returned no structured content. {note}")
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


def generate_plan_gemini(question, retry_message="", status_callback=None):
    client = gemini_client()
    model = gemini_model()
    if client is None:
        raise RuntimeError("Gemini client is not configured.")

    try:
        notify_status(status_callback, "Thinking through the request...")
        throttle_provider("gemini", status_callback=status_callback)
        notify_status(status_callback, "Drafting a SQL plan...")
        response = client.models.generate_content(
            model=model,
            contents=user_prompt(question, retry_message),
            config=genai_types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0,
                max_output_tokens=512,
                response_mime_type="application/json",
                response_json_schema=sanitize_json_schema(PLAN_SCHEMA),
            ),
        )
        usage = _gemini_usage(response)
        parsed = _read_value(response, "parsed")
        if isinstance(parsed, Plan):
            text = parsed.model_dump_json()
        elif isinstance(parsed, dict):
            text = json.dumps(parsed)
        else:
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


def generate_plan(question, retry_message="", status_callback=None, provider=None):
    selected_provider = provider or preferred_provider()
    if selected_provider == "cerebras":
        if not api_key():
            raise RuntimeError("CEREBRAS_API_KEY is not set.")
        try:
            return generate_plan_cerebras(question, retry_message, status_callback=status_callback)
        except Exception as error:
            if _error_status(error) == 429 and gemini_api_key():
                notify_status(status_callback, "Cerebras is busy right now. Falling back to Google...")
                log_stdout("fallback provider=cerebras->gemini reason=429")
                return generate_plan_gemini(question, retry_message, status_callback=status_callback)
            raise
    if selected_provider == "gemini":
        if not gemini_api_key():
            raise RuntimeError("GEMINI_API_KEY is not set.")
        return generate_plan_gemini(question, retry_message, status_callback=status_callback)
    raise RuntimeError("Set CEREBRAS_API_KEY or GEMINI_API_KEY in .env to use AI query.")


def resolve_query(db_path, question, max_attempts=3, status_callback=None, provider=None):
    retry_message = ""
    last_error = None

    for attempt in range(1, max_attempts + 1):
        log_stdout(f"resolve attempt={attempt}/{max_attempts} question={question!r}")
        raw = generate_plan(question, retry_message, status_callback=status_callback, provider=provider)
        try:
            plan = parse_plan(raw)
            if plan["action"] == "ask_clarification":
                notify_status(status_callback, "I need one detail before I run the query...")
                log_stdout(f"planner requested clarification question={plan['clarification_question']!r}")
                return plan

            notify_status(status_callback, "Validating the SQL against the database...")
            sql = validate_sql(plan["sql"])
            validate_sql_with_sqlite(db_path, sql)
            notify_status(status_callback, "Running the query...")
            rows = fetch_all(db_path, sql)
            notify_status(status_callback, "Query complete. Preparing the results...")
            log_stdout(f"sql accepted rows={len(rows)}")
            return {"action": "run_sql", "sql": sql, "rows": rows}
        except Exception as error:
            last_error = error
            retry_message = str(error)
            notify_status(status_callback, f"That query plan did not validate: {retry_message}")
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
