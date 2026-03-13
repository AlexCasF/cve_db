from pathlib import Path
import sqlite3


ROOT_DIR = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT_DIR / "schema.sql"


def connect(db_path):
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db(db_path):
    with connect(db_path) as connection:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))


def clean_text(value):
    if value is None:
        return ""
    return str(value).strip()


def clean_float(value):
    text = clean_text(value)
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def upsert_vendor(connection, name):
    name = clean_text(name) or "unknown_vendor"
    connection.execute("INSERT OR IGNORE INTO vendors(name) VALUES(?)", (name,))
    row = connection.execute(
        "SELECT vendor_id FROM vendors WHERE name = ?",
        (name,),
    ).fetchone()
    return row["vendor_id"]


def upsert_product(connection, vendor_id, name):
    name = clean_text(name) or "unknown_product"
    connection.execute(
        "INSERT OR IGNORE INTO products(vendor_id, name) VALUES(?, ?)",
        (vendor_id, name),
    )
    row = connection.execute(
        "SELECT product_id FROM products WHERE vendor_id = ? AND name = ?",
        (vendor_id, name),
    ).fetchone()
    return row["product_id"]


def upsert_cve(connection, record):
    cve_id = clean_text(record.get("cve_id"))
    if not cve_id:
        raise ValueError("cve_id is required")

    connection.execute(
        """
        INSERT INTO cves(cve_id, description, published, last_modified, severity, cvss_score, source, url)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            description = excluded.description,
            published = excluded.published,
            last_modified = excluded.last_modified,
            severity = excluded.severity,
            cvss_score = excluded.cvss_score,
            source = excluded.source,
            url = excluded.url
        """,
        (
            cve_id,
            clean_text(record.get("description")) or "(no description)",
            clean_text(record.get("published")) or None,
            clean_text(record.get("last_modified")) or None,
            clean_text(record.get("severity")) or None,
            clean_float(record.get("cvss_score")),
            clean_text(record.get("source")) or None,
            clean_text(record.get("url")) or None,
        ),
    )

    connection.execute("DELETE FROM cve_products WHERE cve_id = ?", (cve_id,))
    for vendor_name, product_name in record.get("affected", []):
        vendor_id = upsert_vendor(connection, vendor_name)
        product_id = upsert_product(connection, vendor_id, product_name)
        connection.execute(
            "INSERT OR IGNORE INTO cve_products(cve_id, product_id) VALUES(?, ?)",
            (cve_id, product_id),
        )


def save_records(db_path, records):
    with connect(db_path) as connection:
        for record in records:
            upsert_cve(connection, record)
    return len(records)


def fetch_all(db_path, sql, params=()):
    with connect(db_path) as connection:
        rows = connection.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def fetch_one(db_path, sql, params=()):
    rows = fetch_all(db_path, sql, params)
    if not rows:
        return None
    return rows[0]


def print_rows(rows, limit=10):
    if not rows:
        print("No rows found.")
        return

    shown = rows[:limit]
    columns = list(shown[0].keys())
    widths = {}
    for column in columns:
        cell_lengths = [len(str(row.get(column, ""))) for row in shown]
        widths[column] = max(len(column), min(max(cell_lengths), 40))

    header = " | ".join(column.ljust(widths[column]) for column in columns)
    divider = "-+-".join("-" * widths[column] for column in columns)
    print(header)
    print(divider)

    for row in shown:
        values = []
        for column in columns:
            text = str(row.get(column, ""))
            if len(text) > widths[column]:
                text = text[: widths[column] - 3] + "..."
            values.append(text.ljust(widths[column]))
        print(" | ".join(values))

    if len(rows) > limit:
        print(f"... showing {limit} of {len(rows)} rows")
