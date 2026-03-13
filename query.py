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

ALLOWED_TABLES = {
    "cves",
    "vendors",
    "products",
    "cve_products",
    "cve_tags",
    "cve_descriptions",
    "cve_metrics",
    "cve_weaknesses",
    "cve_weakness_descriptions",
    "cve_references",
    "cve_reference_tags",
    "cve_configurations",
    "cve_nodes",
    "cve_matches",
    "cve_match_names",
    "nvd_cpes",
    "nvd_cpe_titles",
    "nvd_cpe_refs",
    "nvd_cpe_deprecates",
    "nvd_cpe_deprecated_by",
    "nvd_match_strings",
    "nvd_match_string_matches",
    "nvd_sources",
    "nvd_source_identifiers",
    "nvd_source_acceptance_levels",
    "nvd_cve_changes",
    "nvd_cve_change_details",
}
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
SYSTEM_PROMPT = f"""
Return only JSON matching the provided schema. No markdown, no prose, no code fences. Keep the JSON minified and the SQL on one line.
Today is {date.today().isoformat()}.

Allowed tables:
- cves, vendors, products, cve_products
- cve_tags, cve_descriptions, cve_metrics, cve_weaknesses, cve_weakness_descriptions, cve_references, cve_reference_tags
- cve_configurations, cve_nodes, cve_matches, cve_match_names
- nvd_cpes, nvd_cpe_titles, nvd_cpe_refs, nvd_cpe_deprecates, nvd_cpe_deprecated_by
- nvd_match_strings, nvd_match_string_matches
- nvd_sources, nvd_source_identifiers, nvd_source_acceptance_levels
- nvd_cve_changes, nvd_cve_change_details

Use SELECT only. Never use raw_* tables or sync_state.
Ask one clarification question only if the request is too vague.
For latest/newest, order CVEs by COALESCE(c.published, c.last_modified) DESC.
For one bug use LIMIT 1. Otherwise use the requested count or LIMIT 20.
Prefer the shortest correct SQL. Use DISTINCT when joins can duplicate CVEs.

Use cves first for simple CVE listing, score/date filters, and keyword searches.
For normal CVE result lists, prefer these columns when available: cve_id, description, published, last_modified, severity, cvss_score, source_identifier, source, url.
Use the official product path only when vendor/product identity matters:
cves.cve_id = cve_configurations.cve_id
cve_configurations.configuration_id = cve_nodes.configuration_id
cve_nodes.node_id = cve_matches.node_id
cve_matches.match_criteria_id = nvd_match_strings.match_criteria_id
nvd_match_strings.match_criteria_id = nvd_match_string_matches.match_criteria_id
nvd_match_string_matches.cpe_name_id = nvd_cpes.cpe_name_id
Important: nvd_match_strings has no match_id column.

Use nvd_sources and nvd_source_identifiers for source/CNA/assigner/provider questions.
Use nvd_cve_changes and nvd_cve_change_details for history/what-changed questions.

Matching guidance:
- vendor/product names are often lowercase
- prefer LOWER(column) LIKE '%term%' for names
- for company terms like microsoft, adobe, oracle: prefer official CPE vendor matching
- for product/platform terms like linux, windows, openssh, openclaw: prefer broad matching across cves.description, cves.cve_id, nvd_cpes.vendor, nvd_cpes.product, and nvd_cpe_titles.title when useful
- if a broad cves query answers the question, prefer it over a long mirror join
- non-obvious text columns: cves.description is the main summary text, cve_descriptions uses value, nvd_cpe_titles uses title, nvd_cve_change_details has action/type/old_value/new_value and no description column

Examples:
- latest openclaw bug -> broad CVE/product keyword search, newest first, LIMIT 1
- latest 5 openclaw bugs -> same pattern, LIMIT 5
- latest 20 microsoft issues -> official CPE vendor matching, DISTINCT CVEs, newest first
- CVEs whose source is MITRE -> source_identifier join to nvd_sources/nvd_source_identifiers
- what changed for CVE-2024-1234 -> nvd_cve_changes join nvd_cve_change_details ordered by created
- bad ones -> ask what CVSS threshold counts as bad
""".strip()
AI_METRICS = {
    "requests": 0,
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "total_tokens": 0,
    "by_provider": {"cerebras": 0, "gemini": 0},
    "events": [],
}
DEFAULT_CVE_COLUMNS = [
    "cve_id",
    "description",
    "published",
    "last_modified",
    "severity",
    "cvss_score",
    "source_identifier",
    "source",
    "url",
]


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
    alias_map = {}
    table_refs = re.findall(
        r"\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_]*)(?:\s+(?:as\s+)?([a-zA-Z_][a-zA-Z0-9_]*))?",
        cleaned,
        re.IGNORECASE,
    )
    for table, alias in table_refs:
        table_lower = table.lower()
        if table_lower not in ALLOWED_TABLES:
            raise ValueError(f"Table not allowed: {table}")
        alias_map[table_lower] = table_lower
        if alias:
            alias_map[alias.lower()] = table_lower

    wrong_column_hints = {
        "cve_descriptions": {"description": "value"},
        "nvd_cpe_titles": {"description": "title"},
        "nvd_cve_change_details": {"description": "action/type/old_value/new_value"},
    }
    for alias, table in alias_map.items():
        for wrong_column, correct_column in wrong_column_hints.get(table, {}).items():
            if re.search(rf"\b{re.escape(alias)}\.{re.escape(wrong_column)}\b", cleaned, re.IGNORECASE):
                raise ValueError(
                    f"{table} does not have {wrong_column}; use {correct_column} instead."
                )
    if not re.search(r"\blimit\b", cleaned, re.IGNORECASE):
        cleaned = f"{cleaned} LIMIT 20"
    return cleaned


def validate_sql_with_sqlite(db_path, sql):
    with sqlite3.connect(db_path) as connection:
        connection.execute(f"EXPLAIN QUERY PLAN {sql}")


def enrich_cve_rows(db_path, rows):
    if not rows:
        return rows
    if "cve_id" not in rows[0]:
        return rows
    if all(column in rows[0] for column in DEFAULT_CVE_COLUMNS):
        return rows

    cve_ids = []
    for row in rows:
        cve_id = row.get("cve_id")
        if cve_id and cve_id not in cve_ids:
            cve_ids.append(cve_id)
    if not cve_ids:
        return rows

    placeholders = ",".join("?" for _ in cve_ids)
    details = fetch_all(
        db_path,
        f"""
        SELECT cve_id, description, published, last_modified, severity, cvss_score, source_identifier, source, url
        FROM cves
        WHERE cve_id IN ({placeholders})
        """,
        tuple(cve_ids),
    )
    detail_map = {row["cve_id"]: row for row in details}

    enriched = []
    for row in rows:
        detail = detail_map.get(row.get("cve_id"), {})
        merged = {}
        for column in DEFAULT_CVE_COLUMNS:
            if column in row:
                merged[column] = row[column]
            elif column in detail:
                merged[column] = detail[column]
        for key, value in row.items():
            if key not in merged:
                merged[key] = value
        enriched.append(merged)
    return enriched


def user_prompt(question, retry_message=""):
    retry_block = ""
    if retry_message:
        extra_hint = ""
        if "no such column" in retry_message.lower() or "does not have" in retry_message.lower():
            extra_hint = (
                "Re-check the real column names. Use cves.description for the main CVE summary, "
                "cve_descriptions.value for multilingual descriptions, nvd_cpe_titles.title for CPE titles, "
                "and nvd_cve_change_details.action/type/old_value/new_value for change-history details.\n"
            )
        retry_block = (
            "Previous attempt was invalid. Fix it.\n"
            f"Validation error: {retry_message}\n"
            f"{extra_hint}"
        )
    return (
        f"{retry_block}"
        "Return minified JSON only. No markdown. No explanations. SQL must be one line.\n"
        f"User request:\n{question}"
    )


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


def generate_plan_cerebras(question, retry_message="", status_callback=None):
    client = cerebras_client()
    model = model_name()
    if client is None:
        raise RuntimeError("Cerebras client is not configured.")

    try:
        notify_status(status_callback, "Thinking through the request...")
        throttle_provider("cerebras", status_callback=status_callback)
        notify_status(status_callback, "Drafting a SQL plan...")
        completion = client.chat.completions.create(
            model=model,
            reasoning_effort="low",
            reasoning_format="hidden",
            temperature=0,
            max_completion_tokens=512,
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
                max_output_tokens=320,
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


def resolve_query(db_path, question, max_attempts=2, status_callback=None, provider=None):
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
            rows = enrich_cve_rows(db_path, rows)
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
