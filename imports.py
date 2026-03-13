import csv
import json
import re
from pathlib import Path

from db import clean_float, clean_text, fetch_all, fetch_one, print_rows, save_records


def parse_cpe(uri):
    parts = clean_text(uri).split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return (
        (parts[3] or "unknown_vendor").replace("_", " ").lower(),
        (parts[4] or "unknown_product").replace("_", " ").lower(),
    )


def split_cpe23(uri):
    parts = clean_text(uri).split(":")
    if len(parts) < 13 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return {
        "part": parts[2] or None,
        "vendor": (parts[3] or "").replace("_", " ").lower() or None,
        "product": (parts[4] or "").replace("_", " ").lower() or None,
        "version": parts[5] or None,
        "update_value": parts[6] or None,
        "edition": parts[7] or None,
        "language": parts[8] or None,
        "sw_edition": parts[9] or None,
        "target_sw": parts[10] or None,
        "target_hw": parts[11] or None,
        "other_value": parts[12] or None,
    }


def extract_descriptions(cve):
    descriptions = []
    for entry in cve.get("descriptions", []):
        if not isinstance(entry, dict):
            continue
        lang = clean_text(entry.get("lang"))
        value = clean_text(entry.get("value"))
        if lang and value:
            descriptions.append({"lang": lang, "value": value})
    return descriptions


def choose_summary_description(descriptions):
    for entry in descriptions:
        if entry.get("lang") == "en":
            return entry["value"]
    if descriptions:
        return descriptions[0]["value"]
    return ""


def extract_metrics(cve):
    metrics = []
    metrics_block = cve.get("metrics", {})
    if not isinstance(metrics_block, dict):
        return metrics

    for metric_key, values in metrics_block.items():
        if not isinstance(values, list):
            continue
        for metric_index, value in enumerate(values):
            if not isinstance(value, dict):
                continue
            cvss_data = value.get("cvssData", {}) if isinstance(value.get("cvssData"), dict) else {}
            metrics.append(
                {
                    "metric_key": clean_text(metric_key),
                    "metric_index": metric_index,
                    "source": clean_text(value.get("source")) or None,
                    "type": clean_text(value.get("type")) or None,
                    "version": clean_text(cvss_data.get("version")) or None,
                    "vector_string": clean_text(cvss_data.get("vectorString")) or None,
                    "base_severity": clean_text(cvss_data.get("baseSeverity") or value.get("baseSeverity")) or None,
                    "base_score": clean_float(cvss_data.get("baseScore")),
                    "exploitability_score": clean_float(value.get("exploitabilityScore")),
                    "impact_score": clean_float(value.get("impactScore")),
                    "data_json": json.dumps(value, ensure_ascii=True, separators=(",", ":")),
                }
            )
    return metrics


def choose_primary_metric(metrics):
    if not metrics:
        return None

    for metric in metrics:
        if metric.get("source") == "nvd@nist.gov":
            return metric
    return metrics[0]


def extract_weaknesses(cve):
    weaknesses = []
    for weakness_index, value in enumerate(cve.get("weaknesses", [])):
        if not isinstance(value, dict):
            continue
        descriptions = []
        for entry in value.get("description", []):
            if not isinstance(entry, dict):
                continue
            lang = clean_text(entry.get("lang"))
            text = clean_text(entry.get("value"))
            if lang and text:
                descriptions.append({"lang": lang, "value": text})
        weaknesses.append(
            {
                "weakness_index": weakness_index,
                "source": clean_text(value.get("source")) or None,
                "type": clean_text(value.get("type")) or None,
                "descriptions": descriptions,
            }
        )
    return weaknesses


def extract_references(cve):
    references = []
    for reference_index, value in enumerate(cve.get("references", [])):
        if not isinstance(value, dict):
            continue
        url = clean_text(value.get("url"))
        if not url:
            continue
        tags = []
        for tag in value.get("tags", []):
            text = clean_text(tag)
            if text:
                tags.append(text)
        references.append(
            {
                "reference_index": reference_index,
                "url": url,
                "source": clean_text(value.get("source")) or None,
                "tags": tags,
            }
        )
    return references


def extract_tags(cve):
    tags = []
    for tag_entry in cve.get("cveTags", []):
        if not isinstance(tag_entry, dict):
            continue
        source_identifier = clean_text(tag_entry.get("sourceIdentifier")) or None
        for tag in tag_entry.get("tags", []):
            value = clean_text(tag)
            if value:
                tags.append({"source_identifier": source_identifier, "tag": value})
    return tags


def extract_matches(node):
    matches = []
    for match_index, value in enumerate(node.get("cpeMatch", [])):
        if not isinstance(value, dict):
            continue
        criteria = clean_text(value.get("criteria") or value.get("cpe23Uri"))
        if not criteria:
            continue
        names = []
        for entry in value.get("matches", []):
            if not isinstance(entry, dict):
                continue
            cpe_name = clean_text(entry.get("cpeName"))
            if cpe_name:
                names.append(
                    {
                        "cpe_name": cpe_name,
                        "cpe_name_id": clean_text(entry.get("cpeNameId")) or None,
                    }
                )
        matches.append(
            {
                "match_index": match_index,
                "vulnerable": bool(value.get("vulnerable")),
                "criteria": criteria,
                "match_criteria_id": clean_text(value.get("matchCriteriaId")) or None,
                "version_start_including": clean_text(value.get("versionStartIncluding")) or None,
                "version_start_excluding": clean_text(value.get("versionStartExcluding")) or None,
                "version_end_including": clean_text(value.get("versionEndIncluding")) or None,
                "version_end_excluding": clean_text(value.get("versionEndExcluding")) or None,
                "names": names,
            }
        )
    return matches


def extract_nodes(nodes):
    normalized = []
    for node_index, node in enumerate(nodes):
        if not isinstance(node, dict):
            continue
        normalized.append(
            {
                "node_index": node_index,
                "operator": clean_text(node.get("operator")) or None,
                "negate": bool(node.get("negate")),
                "matches": extract_matches(node),
                "children": extract_nodes(node.get("children", [])),
            }
        )
    return normalized


def extract_configurations(cve):
    configurations = []
    for configuration_index, config in enumerate(cve.get("configurations", [])):
        if not isinstance(config, dict):
            continue
        configurations.append(
            {
                "configuration_index": configuration_index,
                "nodes": extract_nodes(config.get("nodes", [])),
            }
        )
    return configurations


def collect_affected_pairs(configurations):
    affected = set()

    def walk(nodes):
        for node in nodes:
            for match in node.get("matches", []):
                pair = parse_cpe(match.get("criteria"))
                if pair:
                    affected.add(pair)
            walk(node.get("children", []))

    for configuration in configurations:
        walk(configuration.get("nodes", []))

    return sorted(affected)


def parse_nvd_record(item):
    cve = item.get("cve", {})
    cve_id = clean_text(cve.get("id"))
    if not cve_id:
        return None

    descriptions = extract_descriptions(cve)
    metrics = extract_metrics(cve)
    primary_metric = choose_primary_metric(metrics)
    configurations = extract_configurations(cve)

    return {
        "cve_id": cve_id,
        "source_identifier": clean_text(cve.get("sourceIdentifier")) or None,
        "vuln_status": clean_text(cve.get("vulnStatus")) or None,
        "published": clean_text(cve.get("published")) or None,
        "last_modified": clean_text(cve.get("lastModified")) or None,
        "evaluator_comment": clean_text(cve.get("evaluatorComment")) or None,
        "evaluator_impact": clean_text(cve.get("evaluatorImpact")) or None,
        "evaluator_solution": clean_text(cve.get("evaluatorSolution")) or None,
        "cisa_exploit_add": clean_text(cve.get("cisaExploitAdd")) or None,
        "cisa_action_due": clean_text(cve.get("cisaActionDue")) or None,
        "cisa_required_action": clean_text(cve.get("cisaRequiredAction")) or None,
        "cisa_vulnerability_name": clean_text(cve.get("cisaVulnerabilityName")) or None,
        "description": choose_summary_description(descriptions),
        "severity": primary_metric.get("base_severity") if primary_metric else None,
        "cvss_score": primary_metric.get("base_score") if primary_metric else None,
        "source": "NVD",
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "raw_json": json.dumps(item, ensure_ascii=True, separators=(",", ":")),
        "tags": extract_tags(cve),
        "descriptions": descriptions,
        "metrics": metrics,
        "weaknesses": extract_weaknesses(cve),
        "references": extract_references(cve),
        "configurations": configurations,
        "affected": collect_affected_pairs(configurations),
    }


def parse_nvd_cpe_record(item):
    cpe = item.get("cpe", {})
    cpe_name = clean_text(cpe.get("cpeName"))
    cpe_name_id = clean_text(cpe.get("cpeNameId"))
    if not cpe_name or not cpe_name_id:
        return None

    components = split_cpe23(cpe_name) or {}
    titles = []
    for value in cpe.get("titles", []):
        if not isinstance(value, dict):
            continue
        lang = clean_text(value.get("lang"))
        title = clean_text(value.get("title"))
        if lang and title:
            titles.append({"lang": lang, "title": title})

    refs = []
    for ref_index, value in enumerate(cpe.get("refs", [])):
        if not isinstance(value, dict):
            continue
        ref = clean_text(value.get("ref"))
        if ref:
            refs.append(
                {
                    "ref_index": ref_index,
                    "ref": ref,
                    "type": clean_text(value.get("type")) or None,
                }
            )

    deprecates = []
    for value in cpe.get("deprecates", []):
        if not isinstance(value, dict):
            continue
        related_name = clean_text(value.get("cpeName"))
        if related_name:
            deprecates.append(
                {
                    "related_cpe_name": related_name,
                    "related_cpe_name_id": clean_text(value.get("cpeNameId")) or None,
                }
            )

    deprecated_by = []
    for value in cpe.get("deprecatedBy", []):
        if not isinstance(value, dict):
            continue
        related_name = clean_text(value.get("cpeName"))
        if related_name:
            deprecated_by.append(
                {
                    "related_cpe_name": related_name,
                    "related_cpe_name_id": clean_text(value.get("cpeNameId")) or None,
                }
            )

    return {
        "cpe_name_id": cpe_name_id,
        "cpe_name": cpe_name,
        "created": clean_text(cpe.get("created")) or None,
        "last_modified": clean_text(cpe.get("lastModified")) or None,
        "deprecated": bool(cpe.get("deprecated")),
        "titles": titles,
        "refs": refs,
        "deprecates": deprecates,
        "deprecated_by": deprecated_by,
        "raw_json": json.dumps(item, ensure_ascii=True, separators=(",", ":")),
        **components,
    }


def parse_nvd_cpematch_record(item):
    match_string = item.get("matchString", {})
    match_criteria_id = clean_text(match_string.get("matchCriteriaId"))
    criteria = clean_text(match_string.get("criteria"))
    if not match_criteria_id or not criteria:
        return None

    matches = []
    for value in match_string.get("matches", []):
        if not isinstance(value, dict):
            continue
        cpe_name = clean_text(value.get("cpeName"))
        if cpe_name:
            matches.append(
                {
                    "cpe_name": cpe_name,
                    "cpe_name_id": clean_text(value.get("cpeNameId")) or None,
                }
            )

    return {
        "match_criteria_id": match_criteria_id,
        "criteria": criteria,
        "version_start_including": clean_text(match_string.get("versionStartIncluding")) or None,
        "version_start_excluding": clean_text(match_string.get("versionStartExcluding")) or None,
        "version_end_including": clean_text(match_string.get("versionEndIncluding")) or None,
        "version_end_excluding": clean_text(match_string.get("versionEndExcluding")) or None,
        "created": clean_text(match_string.get("created")) or None,
        "last_modified": clean_text(match_string.get("lastModified")) or None,
        "cpe_last_modified": clean_text(match_string.get("cpeLastModified")) or None,
        "status": clean_text(match_string.get("status")) or None,
        "matches_count": len(matches),
        "matches": matches,
        "raw_json": json.dumps(item, ensure_ascii=True, separators=(",", ":")),
    }


def parse_nvd_source_record(item):
    name = clean_text(item.get("name"))
    if not name:
        return None

    identifiers = []
    for value in item.get("sourceIdentifiers", []):
        identifier = clean_text(value)
        if identifier:
            identifiers.append(identifier)

    acceptance_levels = []
    for key, value in item.items():
        if not key.endswith("AcceptanceLevel") or not isinstance(value, dict):
            continue
        acceptance_levels.append(
            {
                "level_type": key,
                "description": clean_text(value.get("description")) or None,
                "last_modified": clean_text(value.get("lastModified")) or None,
            }
        )

    return {
        "source_name": name,
        "contact_email": clean_text(item.get("contactEmail")) or None,
        "created": clean_text(item.get("created")) or None,
        "last_modified": clean_text(item.get("lastModified")) or None,
        "identifiers": identifiers,
        "acceptance_levels": acceptance_levels,
        "raw_json": json.dumps(item, ensure_ascii=True, separators=(",", ":")),
    }


def parse_nvd_cvehistory_record(item):
    change = item.get("change", {})
    cve_change_id = clean_text(change.get("cveChangeId"))
    cve_id = clean_text(change.get("cveId"))
    if not cve_change_id or not cve_id:
        return None

    details = []
    for detail_index, value in enumerate(change.get("details", [])):
        if not isinstance(value, dict):
            continue
        details.append(
            {
                "detail_index": detail_index,
                "action": clean_text(value.get("action")) or None,
                "type": clean_text(value.get("type")) or None,
                "old_value": clean_text(value.get("oldValue")) or None,
                "new_value": clean_text(value.get("newValue")) or None,
            }
        )

    return {
        "cve_change_id": cve_change_id,
        "cve_id": cve_id,
        "event_name": clean_text(change.get("eventName")) or None,
        "source_identifier": clean_text(change.get("sourceIdentifier")) or None,
        "created": clean_text(change.get("created")) or None,
        "details": details,
        "raw_json": json.dumps(item, ensure_ascii=True, separators=(",", ":")),
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
        "source_identifier": None,
        "vuln_status": None,
        "published": clean_text(row.get("published") or row.get("published_date")) or None,
        "last_modified": clean_text(row.get("last_modified") or row.get("updated")) or None,
        "evaluator_comment": None,
        "evaluator_impact": None,
        "evaluator_solution": None,
        "cisa_exploit_add": None,
        "cisa_action_due": None,
        "cisa_required_action": None,
        "cisa_vulnerability_name": None,
        "description": clean_text(row.get("description") or row.get("summary")),
        "severity": clean_text(row.get("severity")) or None,
        "cvss_score": clean_float(row.get("cvss_score") or row.get("score") or row.get("cvss")),
        "source": source,
        "url": clean_text(row.get("url")) or None,
        "raw_json": json.dumps(row, ensure_ascii=True, separators=(",", ":")),
        "tags": [],
        "descriptions": [{"lang": "en", "value": clean_text(row.get("description") or row.get("summary"))}]
        if clean_text(row.get("description") or row.get("summary"))
        else [],
        "metrics": [],
        "weaknesses": [],
        "references": [{"reference_index": 0, "url": clean_text(row.get("url")), "source": source, "tags": []}]
        if clean_text(row.get("url"))
        else [],
        "configurations": [],
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
