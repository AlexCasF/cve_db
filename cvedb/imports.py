import csv
import json
import re
from pathlib import Path

from cvedb.db import clean_float, clean_text, fetch_all, fetch_one, print_rows, save_records


def parse_cpe(uri):
    parts = clean_text(uri).split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return (
        (parts[3] or "unknown_vendor").replace("_", " ").lower(),
        (parts[4] or "unknown_product").replace("_", " ").lower(),
    )


def parse_nvd_record(item):
    cve = item.get("cve", {})
    cve_id = clean_text(cve.get("id"))
    if not cve_id:
        return None

    description = ""
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en":
            description = clean_text(entry.get("value"))
            break

    cvss_score = None
    severity = ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = cve.get("metrics", {}).get(key, [])
        if not values:
            continue
        first = values[0]
        cvss_data = first.get("cvssData", {})
        cvss_score = clean_float(cvss_data.get("baseScore"))
        severity = clean_text(cvss_data.get("baseSeverity") or first.get("baseSeverity"))
        break

    affected = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            stack = [node]
            while stack:
                current = stack.pop()
                for match in current.get("cpeMatch", []):
                    pair = parse_cpe(match.get("criteria") or match.get("cpe23Uri"))
                    if pair:
                        affected.add(pair)
                stack.extend(current.get("children", []))

    return {
        "cve_id": cve_id,
        "description": description,
        "published": clean_text(cve.get("published")),
        "last_modified": clean_text(cve.get("lastModified")),
        "severity": severity,
        "cvss_score": cvss_score,
        "source": "NVD",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "affected": sorted(affected),
    }


def parse_record(row, source):
    cve_id = clean_text(row.get("cve_id") or row.get("id") or row.get("cve"))
    if not cve_id:
        return None

    vendors = [value.strip() for value in re.split(r"[;,|]", clean_text(row.get("vendor"))) if value.strip()]
    products = [value.strip() for value in re.split(r"[;,|]", clean_text(row.get("product"))) if value.strip()]
    affected = [(vendor, product) for vendor in vendors for product in products]

    return {
        "cve_id": cve_id,
        "description": clean_text(row.get("description") or row.get("summary")),
        "published": clean_text(row.get("published") or row.get("published_date")),
        "last_modified": clean_text(row.get("last_modified") or row.get("updated")),
        "severity": clean_text(row.get("severity")),
        "cvss_score": clean_float(row.get("cvss_score") or row.get("score") or row.get("cvss")),
        "source": source,
        "url": clean_text(row.get("url")),
        "affected": affected,
    }


def load_records(file_path):
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(path)

    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8", newline="") as handle:
            return [record for record in (parse_record(row, "CSV import") for row in csv.DictReader(handle)) if record]

    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), list):
            return [
                record
                for record in (parse_nvd_record(item) for item in payload["vulnerabilities"] if isinstance(item, dict))
                if record
            ]
        if isinstance(payload, list):
            return [record for record in (parse_record(item, "JSON import") for item in payload if isinstance(item, dict)) if record]
        if isinstance(payload, dict):
            record = parse_record(payload, "JSON import")
            return [record] if record else []

    raise ValueError("Only .csv and .json files are supported.")


def import_file(db_path):
    file_path = input("\nPath to CSV or JSON file: ").strip()
    if not file_path:
        print("File path is required.")
        return

    try:
        count = save_records(db_path, load_records(file_path))
    except Exception as error:
        print(f"Import failed: {error}")
        return

    print(f"Imported {count} records.")


def get_stats(db_path):
    return fetch_one(
        db_path,
        "SELECT COUNT(*) AS total_cves, ROUND(AVG(cvss_score), 2) AS average_cvss FROM cves",
    ) or {}


def get_top_vendors(db_path):
    return fetch_all(
        db_path,
        """
        SELECT vendors.name AS vendor, COUNT(DISTINCT cve_products.cve_id) AS vuln_count
        FROM vendors
        LEFT JOIN products ON products.vendor_id = vendors.vendor_id
        LEFT JOIN cve_products ON cve_products.product_id = products.product_id
        GROUP BY vendors.vendor_id
        ORDER BY vuln_count DESC, vendors.name
        LIMIT 10
        """,
    )


def find_cves(db_path, keyword="", minimum_value=None, limit=20):
    like_keyword = f"%{keyword.lower()}%"
    return fetch_all(
        db_path,
        """
        SELECT cves.cve_id, cves.severity, cves.cvss_score, cves.published, cves.description
        FROM cves
        WHERE (? = '' OR LOWER(cves.cve_id) LIKE ? OR LOWER(cves.description) LIKE ?)
          AND (? IS NULL OR cves.cvss_score >= ?)
        ORDER BY cves.cvss_score DESC, cves.published DESC
        LIMIT ?
        """,
        (keyword.lower(), like_keyword, like_keyword, minimum_value, minimum_value, limit),
    )


def show_stats(db_path):
    stats = get_stats(db_path)
    top_vendors = get_top_vendors(db_path)

    print()
    print(f"Total CVEs: {stats.get('total_cves', 0)}")
    print(f"Average CVSS: {stats.get('average_cvss', 'N/A')}")
    print("\nTop vendors")
    print_rows(top_vendors)


def filter_cves(db_path):
    keyword = input("\nKeyword [optional]: ").strip().lower()
    minimum = input("Minimum CVSS [optional]: ").strip()
    minimum_value = clean_float(minimum)
    if minimum and minimum_value is None:
        print("Invalid CVSS score.")
        return

    rows = find_cves(db_path, keyword=keyword, minimum_value=minimum_value, limit=20)
    print()
    print_rows(rows, limit=20)


def run(db_path):
    while True:
        print("\nImport and analysis")
        print("1. Import CSV or JSON")
        print("2. Show stats")
        print("3. Filter CVEs")
        print("0. Back")
        choice = input("Choose: ").strip()

        if choice == "1":
            import_file(db_path)
        elif choice == "2":
            show_stats(db_path)
        elif choice == "3":
            filter_cves(db_path)
        elif choice == "0":
            return
        else:
            print("Invalid choice.")
