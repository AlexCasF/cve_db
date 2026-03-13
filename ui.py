import os
import tempfile

import streamlit as st
from dotenv import load_dotenv

from db import fetch_all, fetch_one, init_db, save_records
from imports import find_cves, get_stats, get_top_vendors, load_records
from query import api_key, apply_clarification, gemini_api_key, resolve_query
from sync import sync_recent


def render_rows(rows, title=None, limit=25):
    if title:
        st.caption(title)
    if not rows:
        st.info("No rows found.")
        return

    shown = rows[:limit]
    columns = list(shown[0].keys())
    header = "| " + " | ".join(columns) + " |"
    divider = "| " + " | ".join(["---"] * len(columns)) + " |"
    body = []
    for row in shown:
        values = [str(row.get(column, "")).replace("\n", " ") for column in columns]
        body.append("| " + " | ".join(values) + " |")
    st.markdown("\n".join([header, divider, *body]))
    if len(rows) > limit:
        st.caption(f"Showing {limit} of {len(rows)} rows.")


def render_bars(rows, label_key, value_key, title):
    st.caption(title)
    if not rows:
        st.info("No data yet.")
        return

    max_value = max(int(row.get(value_key, 0) or 0) for row in rows) or 1
    for row in rows:
        label = str(row.get(label_key, ""))
        value = int(row.get(value_key, 0) or 0)
        st.write(f"{label}: {value}")
        st.progress(min(value / max_value, 1.0))


def render_search(db_path):
    st.subheader("Search and entry")
    left, right = st.columns(2)

    with left:
        with st.form("manual-entry"):
            cve_id = st.text_input("CVE ID")
            description = st.text_area("Description")
            published = st.text_input("Published", placeholder="2026-03-13")
            severity = st.text_input("Severity")
            cvss_score = st.text_input("CVSS score")
            vendor = st.text_input("Vendor")
            product = st.text_input("Product")
            submitted = st.form_submit_button("Save CVE")

        if submitted:
            if not cve_id.strip():
                st.error("CVE ID is required.")
            else:
                save_records(
                    db_path,
                    [
                        {
                            "cve_id": cve_id.strip(),
                            "description": description.strip(),
                            "published": published.strip(),
                            "last_modified": published.strip(),
                            "severity": severity.strip().upper(),
                            "cvss_score": cvss_score.strip(),
                            "source": "manual",
                            "url": "",
                            "affected": [(vendor.strip(), product.strip())] if vendor.strip() and product.strip() else [],
                        }
                    ],
                )
                st.success(f"Saved {cve_id.strip()}.")

    with right:
        lookup_id = st.text_input("Find CVE by ID")
        if lookup_id.strip():
            cve = fetch_one(db_path, "SELECT * FROM cves WHERE cve_id = ?", (lookup_id.strip(),))
            related = fetch_all(
                db_path,
                """
                SELECT vendors.name AS vendor, products.name AS product
                FROM cve_products
                JOIN products ON products.product_id = cve_products.product_id
                JOIN vendors ON vendors.vendor_id = products.vendor_id
                WHERE cve_products.cve_id = ?
                ORDER BY vendors.name, products.name
                """,
                (lookup_id.strip(),),
            )
            if cve:
                st.json(cve)
                if related:
                    render_rows(related, title="Affected products")
            else:
                st.info("No matching CVE found.")

    st.divider()
    keyword, minimum = st.columns(2)
    with keyword:
        keyword_value = st.text_input("Keyword filter")
    with minimum:
        minimum_value = st.text_input("Minimum CVSS")

    minimum_score = None
    if minimum_value.strip():
        try:
            minimum_score = float(minimum_value)
        except ValueError:
            st.error("Minimum CVSS must be a number.")
            return

    rows = find_cves(db_path, keyword=keyword_value.strip(), minimum_value=minimum_score, limit=50)
    render_rows(rows, title="Matching CVEs", limit=50)


def render_data(db_path):
    st.subheader("Import and sync")
    uploaded = st.file_uploader("Upload CSV or JSON", type=["csv", "json"])
    if uploaded is not None and st.button("Import file"):
        suffix = os.path.splitext(uploaded.name)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as handle:
            handle.write(uploaded.getvalue())
            temp_path = handle.name
        try:
            records = load_records(temp_path)
            save_records(db_path, records)
            st.success(f"Imported {len(records)} records.")
        except Exception as error:
            st.error(f"Import failed: {error}")
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    st.divider()
    days = st.number_input("Sync CVEs updated in last N days", min_value=1, max_value=365, value=7)
    if st.button("Sync from NIST"):
        try:
            sync_recent(db_path, api_key=os.getenv("NIST_API_KEY", ""), days=int(days))
            st.success("Sync complete.")
        except Exception as error:
            st.error(f"Sync failed: {error}")


def render_analytics(db_path):
    st.subheader("Analytics")
    stats = get_stats(db_path)
    col1, col2, col3 = st.columns(3)
    col1.metric("Total CVEs", stats.get("total_cves", 0))
    col2.metric("Average CVSS", stats.get("average_cvss", "N/A"))
    col3.metric(
        "Critical CVEs",
        fetch_one(db_path, "SELECT COUNT(*) AS count FROM cves WHERE cvss_score >= 9.0")["count"],
    )

    top_vendors = get_top_vendors(db_path)
    severity_rows = fetch_all(
        db_path,
        """
        SELECT COALESCE(NULLIF(TRIM(severity), ''), 'UNKNOWN') AS severity, COUNT(*) AS total
        FROM cves
        GROUP BY COALESCE(NULLIF(TRIM(severity), ''), 'UNKNOWN')
        ORDER BY total DESC
        """,
    )

    left, right = st.columns(2)
    with left:
        render_bars(top_vendors, "vendor", "vuln_count", "Top vendors by CVE count")
        if top_vendors:
            render_rows(top_vendors, limit=10)

    with right:
        render_bars(severity_rows, "severity", "total", "Severity distribution")
        if severity_rows:
            render_rows(severity_rows, limit=10)


def render_chat(db_path):
    st.subheader("NL to SQL chat")
    st.caption("Chat idea: keep SQL visible, let the user refine filters, and show the result table below each reply.")

    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "pending_question" not in st.session_state:
        st.session_state.pending_question = None

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
            if message.get("sql"):
                st.code(message["sql"], language="sql")
            if message.get("rows") is not None:
                render_rows(message["rows"], limit=20)

    prompt = st.chat_input("Example: show microsoft bugs from last month above 8.0")
    if not prompt:
        return

    st.session_state.messages.append({"role": "user", "content": prompt})

    if not api_key() and not gemini_api_key():
        st.session_state.messages.append(
            {"role": "assistant", "content": "Set CEREBRAS_API_KEY or GEMINI_API_KEY in .env to use chat."}
        )
        st.rerun()

    pending_question = st.session_state.pending_question
    full_question = prompt if pending_question is None else apply_clarification(pending_question, prompt)

    try:
        result = resolve_query(db_path, full_question)
        if result["action"] == "ask_clarification":
            st.session_state.pending_question = full_question
            st.session_state.messages.append(
                {"role": "assistant", "content": result["clarification_question"]}
            )
        else:
            st.session_state.pending_question = None
            st.session_state.messages.append(
                {
                    "role": "assistant",
                    "content": f"Returned {len(result['rows'])} row(s).",
                    "sql": result["sql"],
                    "rows": result["rows"],
                }
            )
    except Exception as error:
        st.session_state.messages.append({"role": "assistant", "content": f"Query failed: {error}"})
    st.rerun()


def main():
    load_dotenv()
    st.set_page_config(page_title="Cybersteps CVE DB", layout="wide")
    st.title("Cybersteps CVE DB")
    st.caption("Simple Streamlit frontend ideas: search-first layout, small charts, import/sync controls, and a SQL-visible chat.")

    db_path = st.sidebar.text_input("Database path", value=os.getenv("CVE_DB_PATH", "cve.db"))
    init_db(db_path)

    search_tab, data_tab, analytics_tab, chat_tab = st.tabs(["Search", "Data", "Analytics", "Chat"])
    with search_tab:
        render_search(db_path)
    with data_tab:
        render_data(db_path)
    with analytics_tab:
        render_analytics(db_path)
    with chat_tab:
        render_chat(db_path)


if __name__ == "__main__":
    main()
