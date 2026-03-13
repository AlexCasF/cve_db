from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import sqlite3


ROOT_DIR = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT_DIR / "schema.sql"


def connect(db_path):
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def utc_now_text():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_columns(connection, table_name, columns):
    existing = {
        row["name"]
        for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    }
    for column_name, column_type in columns.items():
        if column_name not in existing:
            connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")


def init_db(db_path):
    with connect(db_path) as connection:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        ensure_columns(
            connection,
            "cves",
            {
                "source_identifier": "TEXT",
                "vuln_status": "TEXT",
                "evaluator_comment": "TEXT",
                "evaluator_impact": "TEXT",
                "evaluator_solution": "TEXT",
                "cisa_exploit_add": "TEXT",
                "cisa_action_due": "TEXT",
                "cisa_required_action": "TEXT",
                "cisa_vulnerability_name": "TEXT",
                "raw_json": "TEXT",
            },
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_vuln_status ON cves(vuln_status)")


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


def payload_hash(payload_json):
    return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


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


def clear_cve_children(connection, cve_id):
    connection.execute("DELETE FROM cve_products WHERE cve_id = ?", (cve_id,))
    connection.execute("DELETE FROM cve_tags WHERE cve_id = ?", (cve_id,))
    connection.execute("DELETE FROM cve_descriptions WHERE cve_id = ?", (cve_id,))
    connection.execute("DELETE FROM cve_metrics WHERE cve_id = ?", (cve_id,))
    connection.execute("DELETE FROM cve_weaknesses WHERE cve_id = ?", (cve_id,))
    connection.execute("DELETE FROM cve_references WHERE cve_id = ?", (cve_id,))
    connection.execute("DELETE FROM cve_configurations WHERE cve_id = ?", (cve_id,))


def insert_descriptions(connection, cve_id, descriptions):
    for description in descriptions:
        lang = clean_text(description.get("lang"))
        value = clean_text(description.get("value"))
        if not lang or not value:
            continue
        connection.execute(
            "INSERT OR IGNORE INTO cve_descriptions(cve_id, lang, value) VALUES(?, ?, ?)",
            (cve_id, lang, value),
        )


def insert_tags(connection, cve_id, tags):
    for tag in tags:
        value = clean_text(tag.get("tag"))
        if not value:
            continue
        connection.execute(
            "INSERT OR IGNORE INTO cve_tags(cve_id, source_identifier, tag) VALUES(?, ?, ?)",
            (cve_id, clean_text(tag.get("source_identifier")) or None, value),
        )


def insert_metrics(connection, cve_id, metrics):
    for metric in metrics:
        connection.execute(
            """
            INSERT OR REPLACE INTO cve_metrics(
                cve_id, metric_key, metric_index, source, type, version, vector_string,
                base_severity, base_score, exploitability_score, impact_score, data_json
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cve_id,
                clean_text(metric.get("metric_key")),
                int(metric.get("metric_index", 0)),
                clean_text(metric.get("source")) or None,
                clean_text(metric.get("type")) or None,
                clean_text(metric.get("version")) or None,
                clean_text(metric.get("vector_string")) or None,
                clean_text(metric.get("base_severity")) or None,
                clean_float(metric.get("base_score")),
                clean_float(metric.get("exploitability_score")),
                clean_float(metric.get("impact_score")),
                clean_text(metric.get("data_json")) or "{}",
            ),
        )


def insert_weaknesses(connection, cve_id, weaknesses):
    for weakness in weaknesses:
        cursor = connection.execute(
            """
            INSERT OR REPLACE INTO cve_weaknesses(cve_id, weakness_index, source, type)
            VALUES(?, ?, ?, ?)
            """,
            (
                cve_id,
                int(weakness.get("weakness_index", 0)),
                clean_text(weakness.get("source")) or None,
                clean_text(weakness.get("type")) or None,
            ),
        )
        weakness_id = cursor.lastrowid
        if not weakness_id:
            row = connection.execute(
                "SELECT weakness_id FROM cve_weaknesses WHERE cve_id = ? AND weakness_index = ?",
                (cve_id, int(weakness.get("weakness_index", 0))),
            ).fetchone()
            weakness_id = row["weakness_id"]
        for description in weakness.get("descriptions", []):
            lang = clean_text(description.get("lang"))
            value = clean_text(description.get("value"))
            if not lang or not value:
                continue
            connection.execute(
                "INSERT OR IGNORE INTO cve_weakness_descriptions(weakness_id, lang, value) VALUES(?, ?, ?)",
                (weakness_id, lang, value),
            )


def insert_references(connection, cve_id, references):
    for reference in references:
        cursor = connection.execute(
            """
            INSERT OR REPLACE INTO cve_references(cve_id, reference_index, url, source)
            VALUES(?, ?, ?, ?)
            """,
            (
                cve_id,
                int(reference.get("reference_index", 0)),
                clean_text(reference.get("url")),
                clean_text(reference.get("source")) or None,
            ),
        )
        reference_id = cursor.lastrowid
        if not reference_id:
            row = connection.execute(
                "SELECT reference_id FROM cve_references WHERE cve_id = ? AND reference_index = ?",
                (cve_id, int(reference.get("reference_index", 0))),
            ).fetchone()
            reference_id = row["reference_id"]
        for tag in reference.get("tags", []):
            value = clean_text(tag)
            if value:
                connection.execute(
                    "INSERT OR IGNORE INTO cve_reference_tags(reference_id, tag) VALUES(?, ?)",
                    (reference_id, value),
                )


def insert_match_names(connection, match_id, names):
    for name in names:
        cpe_name = clean_text(name.get("cpe_name"))
        if not cpe_name:
            continue
        connection.execute(
            """
            INSERT OR IGNORE INTO cve_match_names(match_id, cpe_name, cpe_name_id)
            VALUES(?, ?, ?)
            """,
            (
                match_id,
                cpe_name,
                clean_text(name.get("cpe_name_id")) or None,
            ),
        )


def insert_nodes(connection, configuration_id, nodes, parent_node_id=None):
    for node in nodes:
        cursor = connection.execute(
            """
            INSERT INTO cve_nodes(configuration_id, parent_node_id, node_index, operator, negate)
            VALUES(?, ?, ?, ?, ?)
            """,
            (
                configuration_id,
                parent_node_id,
                int(node.get("node_index", 0)),
                clean_text(node.get("operator")) or None,
                1 if node.get("negate") else 0,
            ),
        )
        node_id = cursor.lastrowid

        for match in node.get("matches", []):
            match_cursor = connection.execute(
                """
                INSERT INTO cve_matches(
                    node_id, match_index, vulnerable, criteria, match_criteria_id,
                    version_start_including, version_start_excluding,
                    version_end_including, version_end_excluding
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    node_id,
                    int(match.get("match_index", 0)),
                    1 if match.get("vulnerable") else 0,
                    clean_text(match.get("criteria")),
                    clean_text(match.get("match_criteria_id")) or None,
                    clean_text(match.get("version_start_including")) or None,
                    clean_text(match.get("version_start_excluding")) or None,
                    clean_text(match.get("version_end_including")) or None,
                    clean_text(match.get("version_end_excluding")) or None,
                ),
            )
            insert_match_names(connection, match_cursor.lastrowid, match.get("names", []))

        insert_nodes(connection, configuration_id, node.get("children", []), parent_node_id=node_id)


def insert_configurations(connection, cve_id, configurations):
    for configuration in configurations:
        cursor = connection.execute(
            """
            INSERT OR REPLACE INTO cve_configurations(cve_id, configuration_index)
            VALUES(?, ?)
            """,
            (
                cve_id,
                int(configuration.get("configuration_index", 0)),
            ),
        )
        configuration_id = cursor.lastrowid
        if not configuration_id:
            row = connection.execute(
                "SELECT configuration_id FROM cve_configurations WHERE cve_id = ? AND configuration_index = ?",
                (cve_id, int(configuration.get("configuration_index", 0))),
            ).fetchone()
            configuration_id = row["configuration_id"]
        insert_nodes(connection, configuration_id, configuration.get("nodes", []))


def insert_affected_products(connection, cve_id, affected_pairs):
    for vendor_name, product_name in affected_pairs:
        vendor_id = upsert_vendor(connection, vendor_name)
        product_id = upsert_product(connection, vendor_id, product_name)
        connection.execute(
            "INSERT OR IGNORE INTO cve_products(cve_id, product_id) VALUES(?, ?)",
            (cve_id, product_id),
        )


def upsert_raw_cve_document(connection, item, api_timestamp=None, fetched_at=None):
    cve = item.get("cve", {}) if isinstance(item, dict) else {}
    cve_id = clean_text(cve.get("id"))
    if not cve_id:
        return

    payload_json = json.dumps(item, ensure_ascii=True, separators=(",", ":"))
    connection.execute(
        """
        INSERT INTO raw_cve_documents(
            cve_id, published, last_modified, api_timestamp, fetched_at, payload_hash, payload_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            published = excluded.published,
            last_modified = excluded.last_modified,
            api_timestamp = excluded.api_timestamp,
            fetched_at = excluded.fetched_at,
            payload_hash = excluded.payload_hash,
            payload_json = excluded.payload_json
        """,
        (
            cve_id,
            clean_text(cve.get("published")) or None,
            clean_text(cve.get("lastModified")) or None,
            clean_text(api_timestamp) or None,
            clean_text(fetched_at) or utc_now_text(),
            payload_hash(payload_json),
            payload_json,
        ),
    )


def upsert_raw_cpe_document(connection, item, api_timestamp=None, fetched_at=None):
    cpe = item.get("cpe", {}) if isinstance(item, dict) else {}
    cpe_name_id = clean_text(cpe.get("cpeNameId"))
    cpe_name = clean_text(cpe.get("cpeName"))
    if not cpe_name_id or not cpe_name:
        return

    payload_json = json.dumps(item, ensure_ascii=True, separators=(",", ":"))
    connection.execute(
        """
        INSERT INTO raw_cpe_documents(
            cpe_name_id, cpe_name, created, last_modified, deprecated,
            api_timestamp, fetched_at, payload_hash, payload_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cpe_name_id) DO UPDATE SET
            cpe_name = excluded.cpe_name,
            created = excluded.created,
            last_modified = excluded.last_modified,
            deprecated = excluded.deprecated,
            api_timestamp = excluded.api_timestamp,
            fetched_at = excluded.fetched_at,
            payload_hash = excluded.payload_hash,
            payload_json = excluded.payload_json
        """,
        (
            cpe_name_id,
            cpe_name,
            clean_text(cpe.get("created")) or None,
            clean_text(cpe.get("lastModified")) or None,
            1 if cpe.get("deprecated") else 0,
            clean_text(api_timestamp) or None,
            clean_text(fetched_at) or utc_now_text(),
            payload_hash(payload_json),
            payload_json,
        ),
    )


def upsert_raw_cpematch_document(connection, item, api_timestamp=None, fetched_at=None):
    match_string = item.get("matchString", {}) if isinstance(item, dict) else {}
    match_criteria_id = clean_text(match_string.get("matchCriteriaId"))
    criteria = clean_text(match_string.get("criteria"))
    if not match_criteria_id or not criteria:
        return

    payload_json = json.dumps(item, ensure_ascii=True, separators=(",", ":"))
    connection.execute(
        """
        INSERT INTO raw_cpematch_documents(
            match_criteria_id, criteria, created, last_modified, status,
            api_timestamp, fetched_at, payload_hash, payload_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(match_criteria_id) DO UPDATE SET
            criteria = excluded.criteria,
            created = excluded.created,
            last_modified = excluded.last_modified,
            status = excluded.status,
            api_timestamp = excluded.api_timestamp,
            fetched_at = excluded.fetched_at,
            payload_hash = excluded.payload_hash,
            payload_json = excluded.payload_json
        """,
        (
            match_criteria_id,
            criteria,
            clean_text(match_string.get("created")) or None,
            clean_text(match_string.get("lastModified")) or None,
            clean_text(match_string.get("status")) or None,
            clean_text(api_timestamp) or None,
            clean_text(fetched_at) or utc_now_text(),
            payload_hash(payload_json),
            payload_json,
        ),
    )


def upsert_raw_source_document(connection, item, api_timestamp=None, fetched_at=None):
    source_name = clean_text(item.get("name")) if isinstance(item, dict) else ""
    if not source_name:
        return

    payload_json = json.dumps(item, ensure_ascii=True, separators=(",", ":"))
    connection.execute(
        """
        INSERT INTO raw_source_documents(
            source_name, contact_email, created, last_modified, api_timestamp,
            fetched_at, payload_hash, payload_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_name) DO UPDATE SET
            contact_email = excluded.contact_email,
            created = excluded.created,
            last_modified = excluded.last_modified,
            api_timestamp = excluded.api_timestamp,
            fetched_at = excluded.fetched_at,
            payload_hash = excluded.payload_hash,
            payload_json = excluded.payload_json
        """,
        (
            source_name,
            clean_text(item.get("contactEmail")) or None,
            clean_text(item.get("created")) or None,
            clean_text(item.get("lastModified")) or None,
            clean_text(api_timestamp) or None,
            clean_text(fetched_at) or utc_now_text(),
            payload_hash(payload_json),
            payload_json,
        ),
    )


def upsert_raw_cvehistory_document(connection, item, api_timestamp=None, fetched_at=None):
    change = item.get("change", {}) if isinstance(item, dict) else {}
    cve_change_id = clean_text(change.get("cveChangeId"))
    cve_id = clean_text(change.get("cveId"))
    if not cve_change_id or not cve_id:
        return

    payload_json = json.dumps(item, ensure_ascii=True, separators=(",", ":"))
    connection.execute(
        """
        INSERT INTO raw_cvehistory_documents(
            cve_change_id, cve_id, event_name, source_identifier, created,
            api_timestamp, fetched_at, payload_hash, payload_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_change_id) DO UPDATE SET
            cve_id = excluded.cve_id,
            event_name = excluded.event_name,
            source_identifier = excluded.source_identifier,
            created = excluded.created,
            api_timestamp = excluded.api_timestamp,
            fetched_at = excluded.fetched_at,
            payload_hash = excluded.payload_hash,
            payload_json = excluded.payload_json
        """,
        (
            cve_change_id,
            cve_id,
            clean_text(change.get("eventName")) or None,
            clean_text(change.get("sourceIdentifier")) or None,
            clean_text(change.get("created")) or None,
            clean_text(api_timestamp) or None,
            clean_text(fetched_at) or utc_now_text(),
            payload_hash(payload_json),
            payload_json,
        ),
    )


def get_sync_state(db_path, endpoint):
    return fetch_one(
        db_path,
        """
        SELECT endpoint, last_start, last_end, last_success_at, last_total_results, last_message
        FROM sync_state
        WHERE endpoint = ?
        """,
        (endpoint,),
    )


def set_sync_state(db_path, endpoint, last_start=None, last_end=None, last_total_results=None, last_message=None):
    with connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO sync_state(endpoint, last_start, last_end, last_success_at, last_total_results, last_message)
            VALUES(?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint) DO UPDATE SET
                last_start = excluded.last_start,
                last_end = excluded.last_end,
                last_success_at = excluded.last_success_at,
                last_total_results = excluded.last_total_results,
                last_message = excluded.last_message
            """,
            (
                endpoint,
                clean_text(last_start) or None,
                clean_text(last_end) or None,
                utc_now_text(),
                last_total_results,
                clean_text(last_message) or None,
            ),
        )


def clear_cpe_children(connection, cpe_name_id):
    connection.execute("DELETE FROM nvd_cpe_titles WHERE cpe_name_id = ?", (cpe_name_id,))
    connection.execute("DELETE FROM nvd_cpe_refs WHERE cpe_name_id = ?", (cpe_name_id,))
    connection.execute("DELETE FROM nvd_cpe_deprecates WHERE cpe_name_id = ?", (cpe_name_id,))
    connection.execute("DELETE FROM nvd_cpe_deprecated_by WHERE cpe_name_id = ?", (cpe_name_id,))


def clear_match_string_children(connection, match_criteria_id):
    connection.execute("DELETE FROM nvd_match_string_matches WHERE match_criteria_id = ?", (match_criteria_id,))


def clear_source_children(connection, source_name):
    connection.execute("DELETE FROM nvd_source_identifiers WHERE source_name = ?", (source_name,))
    connection.execute("DELETE FROM nvd_source_acceptance_levels WHERE source_name = ?", (source_name,))


def clear_cve_change_children(connection, cve_change_id):
    connection.execute("DELETE FROM nvd_cve_change_details WHERE cve_change_id = ?", (cve_change_id,))


def upsert_cpe(connection, record):
    cpe_name_id = clean_text(record.get("cpe_name_id"))
    cpe_name = clean_text(record.get("cpe_name"))
    if not cpe_name_id or not cpe_name:
        raise ValueError("cpe_name_id and cpe_name are required")

    connection.execute(
        """
        INSERT INTO nvd_cpes(
            cpe_name_id, cpe_name, part, vendor, product, version, update_value, edition,
            language, sw_edition, target_sw, target_hw, other_value, created, last_modified,
            deprecated, raw_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cpe_name_id) DO UPDATE SET
            cpe_name = excluded.cpe_name,
            part = excluded.part,
            vendor = excluded.vendor,
            product = excluded.product,
            version = excluded.version,
            update_value = excluded.update_value,
            edition = excluded.edition,
            language = excluded.language,
            sw_edition = excluded.sw_edition,
            target_sw = excluded.target_sw,
            target_hw = excluded.target_hw,
            other_value = excluded.other_value,
            created = excluded.created,
            last_modified = excluded.last_modified,
            deprecated = excluded.deprecated,
            raw_json = excluded.raw_json
        """,
        (
            cpe_name_id,
            cpe_name,
            clean_text(record.get("part")) or None,
            clean_text(record.get("vendor")) or None,
            clean_text(record.get("product")) or None,
            clean_text(record.get("version")) or None,
            clean_text(record.get("update_value")) or None,
            clean_text(record.get("edition")) or None,
            clean_text(record.get("language")) or None,
            clean_text(record.get("sw_edition")) or None,
            clean_text(record.get("target_sw")) or None,
            clean_text(record.get("target_hw")) or None,
            clean_text(record.get("other_value")) or None,
            clean_text(record.get("created")) or None,
            clean_text(record.get("last_modified")) or None,
            1 if record.get("deprecated") else 0,
            clean_text(record.get("raw_json")) or "{}",
        ),
    )

    clear_cpe_children(connection, cpe_name_id)

    for title in record.get("titles", []):
        lang = clean_text(title.get("lang"))
        value = clean_text(title.get("title"))
        if lang and value:
            connection.execute(
                "INSERT OR IGNORE INTO nvd_cpe_titles(cpe_name_id, lang, title) VALUES(?, ?, ?)",
                (cpe_name_id, lang, value),
            )

    for ref in record.get("refs", []):
        value = clean_text(ref.get("ref"))
        if value:
            connection.execute(
                """
                INSERT OR REPLACE INTO nvd_cpe_refs(cpe_name_id, ref_index, ref, type)
                VALUES(?, ?, ?, ?)
                """,
                (
                    cpe_name_id,
                    int(ref.get("ref_index", 0)),
                    value,
                    clean_text(ref.get("type")) or None,
                ),
            )


def upsert_match_string(connection, record):
    match_criteria_id = clean_text(record.get("match_criteria_id"))
    criteria = clean_text(record.get("criteria"))
    if not match_criteria_id or not criteria:
        raise ValueError("match_criteria_id and criteria are required")

    connection.execute(
        """
        INSERT INTO nvd_match_strings(
            match_criteria_id, criteria, version_start_including, version_start_excluding,
            version_end_including, version_end_excluding, created, last_modified,
            cpe_last_modified, status, matches_count, raw_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(match_criteria_id) DO UPDATE SET
            criteria = excluded.criteria,
            version_start_including = excluded.version_start_including,
            version_start_excluding = excluded.version_start_excluding,
            version_end_including = excluded.version_end_including,
            version_end_excluding = excluded.version_end_excluding,
            created = excluded.created,
            last_modified = excluded.last_modified,
            cpe_last_modified = excluded.cpe_last_modified,
            status = excluded.status,
            matches_count = excluded.matches_count,
            raw_json = excluded.raw_json
        """,
        (
            match_criteria_id,
            criteria,
            clean_text(record.get("version_start_including")) or None,
            clean_text(record.get("version_start_excluding")) or None,
            clean_text(record.get("version_end_including")) or None,
            clean_text(record.get("version_end_excluding")) or None,
            clean_text(record.get("created")) or None,
            clean_text(record.get("last_modified")) or None,
            clean_text(record.get("cpe_last_modified")) or None,
            clean_text(record.get("status")) or None,
            int(record.get("matches_count", 0)),
            clean_text(record.get("raw_json")) or "{}",
        ),
    )

    clear_match_string_children(connection, match_criteria_id)
    for match in record.get("matches", []):
        cpe_name = clean_text(match.get("cpe_name"))
        if cpe_name:
            connection.execute(
                """
                INSERT OR IGNORE INTO nvd_match_string_matches(match_criteria_id, cpe_name_id, cpe_name)
                VALUES(?, ?, ?)
                """,
                (
                    match_criteria_id,
                    clean_text(match.get("cpe_name_id")) or None,
                    cpe_name,
                ),
            )


def upsert_source(connection, record):
    source_name = clean_text(record.get("source_name"))
    if not source_name:
        raise ValueError("source_name is required")

    connection.execute(
        """
        INSERT INTO nvd_sources(source_name, contact_email, created, last_modified, raw_json)
        VALUES(?, ?, ?, ?, ?)
        ON CONFLICT(source_name) DO UPDATE SET
            contact_email = excluded.contact_email,
            created = excluded.created,
            last_modified = excluded.last_modified,
            raw_json = excluded.raw_json
        """,
        (
            source_name,
            clean_text(record.get("contact_email")) or None,
            clean_text(record.get("created")) or None,
            clean_text(record.get("last_modified")) or None,
            clean_text(record.get("raw_json")) or "{}",
        ),
    )

    clear_source_children(connection, source_name)

    for identifier in record.get("identifiers", []):
        value = clean_text(identifier)
        if value:
            connection.execute(
                """
                INSERT OR IGNORE INTO nvd_source_identifiers(source_name, source_identifier)
                VALUES(?, ?)
                """,
                (source_name, value),
            )

    for level in record.get("acceptance_levels", []):
        level_type = clean_text(level.get("level_type"))
        if level_type:
            connection.execute(
                """
                INSERT OR REPLACE INTO nvd_source_acceptance_levels(
                    source_name, level_type, description, last_modified
                )
                VALUES(?, ?, ?, ?)
                """,
                (
                    source_name,
                    level_type,
                    clean_text(level.get("description")) or None,
                    clean_text(level.get("last_modified")) or None,
                ),
            )


def upsert_cve_change(connection, record):
    cve_change_id = clean_text(record.get("cve_change_id"))
    cve_id = clean_text(record.get("cve_id"))
    if not cve_change_id or not cve_id:
        raise ValueError("cve_change_id and cve_id are required")

    connection.execute(
        """
        INSERT INTO nvd_cve_changes(cve_change_id, cve_id, event_name, source_identifier, created, raw_json)
        VALUES(?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_change_id) DO UPDATE SET
            cve_id = excluded.cve_id,
            event_name = excluded.event_name,
            source_identifier = excluded.source_identifier,
            created = excluded.created,
            raw_json = excluded.raw_json
        """,
        (
            cve_change_id,
            cve_id,
            clean_text(record.get("event_name")) or None,
            clean_text(record.get("source_identifier")) or None,
            clean_text(record.get("created")) or None,
            clean_text(record.get("raw_json")) or "{}",
        ),
    )

    clear_cve_change_children(connection, cve_change_id)
    for detail in record.get("details", []):
        connection.execute(
            """
            INSERT OR REPLACE INTO nvd_cve_change_details(
                cve_change_id, detail_index, action, type, old_value, new_value
            )
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            (
                cve_change_id,
                int(detail.get("detail_index", 0)),
                clean_text(detail.get("action")) or None,
                clean_text(detail.get("type")) or None,
                clean_text(detail.get("old_value")) or None,
                clean_text(detail.get("new_value")) or None,
            ),
        )

    for related in record.get("deprecates", []):
        related_name = clean_text(related.get("related_cpe_name"))
        if related_name:
            connection.execute(
                """
                INSERT OR IGNORE INTO nvd_cpe_deprecates(cpe_name_id, related_cpe_name_id, related_cpe_name)
                VALUES(?, ?, ?)
                """,
                (
                    cpe_name_id,
                    clean_text(related.get("related_cpe_name_id")) or None,
                    related_name,
                ),
            )

    for related in record.get("deprecated_by", []):
        related_name = clean_text(related.get("related_cpe_name"))
        if related_name:
            connection.execute(
                """
                INSERT OR IGNORE INTO nvd_cpe_deprecated_by(cpe_name_id, related_cpe_name_id, related_cpe_name)
                VALUES(?, ?, ?)
                """,
                (
                    cpe_name_id,
                    clean_text(related.get("related_cpe_name_id")) or None,
                    related_name,
                ),
            )


def upsert_cve(connection, record):
    cve_id = clean_text(record.get("cve_id"))
    if not cve_id:
        raise ValueError("cve_id is required")

    connection.execute(
        """
        INSERT INTO cves(
            cve_id, source_identifier, vuln_status, published, last_modified,
            evaluator_comment, evaluator_impact, evaluator_solution,
            cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name,
            description, severity, cvss_score, source, url, raw_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            source_identifier = excluded.source_identifier,
            vuln_status = excluded.vuln_status,
            published = excluded.published,
            last_modified = excluded.last_modified,
            evaluator_comment = excluded.evaluator_comment,
            evaluator_impact = excluded.evaluator_impact,
            evaluator_solution = excluded.evaluator_solution,
            cisa_exploit_add = excluded.cisa_exploit_add,
            cisa_action_due = excluded.cisa_action_due,
            cisa_required_action = excluded.cisa_required_action,
            cisa_vulnerability_name = excluded.cisa_vulnerability_name,
            description = excluded.description,
            severity = excluded.severity,
            cvss_score = excluded.cvss_score,
            source = excluded.source,
            url = excluded.url,
            raw_json = excluded.raw_json
        """,
        (
            cve_id,
            clean_text(record.get("source_identifier")) or None,
            clean_text(record.get("vuln_status")) or None,
            clean_text(record.get("published")) or None,
            clean_text(record.get("last_modified")) or None,
            clean_text(record.get("evaluator_comment")) or None,
            clean_text(record.get("evaluator_impact")) or None,
            clean_text(record.get("evaluator_solution")) or None,
            clean_text(record.get("cisa_exploit_add")) or None,
            clean_text(record.get("cisa_action_due")) or None,
            clean_text(record.get("cisa_required_action")) or None,
            clean_text(record.get("cisa_vulnerability_name")) or None,
            clean_text(record.get("description")) or "(no description)",
            clean_text(record.get("severity")) or None,
            clean_float(record.get("cvss_score")),
            clean_text(record.get("source")) or None,
            clean_text(record.get("url")) or None,
            clean_text(record.get("raw_json")) or None,
        ),
    )

    clear_cve_children(connection, cve_id)
    insert_tags(connection, cve_id, record.get("tags", []))
    insert_descriptions(connection, cve_id, record.get("descriptions", []))
    insert_metrics(connection, cve_id, record.get("metrics", []))
    insert_weaknesses(connection, cve_id, record.get("weaknesses", []))
    insert_references(connection, cve_id, record.get("references", []))
    insert_configurations(connection, cve_id, record.get("configurations", []))
    insert_affected_products(connection, cve_id, record.get("affected", []))


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
