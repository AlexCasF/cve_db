import os
import time
from datetime import datetime, timedelta, timezone

import requests
from dotenv import load_dotenv

from db import (
    connect,
    get_sync_state,
    set_sync_state,
    upsert_cpe,
    upsert_cve,
    upsert_cve_change,
    upsert_match_string,
    upsert_source,
    upsert_raw_cpe_document,
    upsert_raw_cve_document,
    upsert_raw_cvehistory_document,
    upsert_raw_cpematch_document,
    upsert_raw_source_document,
    utc_now_text,
)
from imports import (
    parse_nvd_cpe_record,
    parse_nvd_cpematch_record,
    parse_nvd_cvehistory_record,
    parse_nvd_record,
    parse_nvd_source_record,
)


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CPEMATCH_API_URL = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"
NVD_SOURCE_API_URL = "https://services.nvd.nist.gov/rest/json/source/2.0"
NVD_CVEHISTORY_API_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
NVD_SYNC_ENDPOINT = "nvd_cves_2_0_last_modified"
NVD_CPE_SYNC_ENDPOINT = "nvd_cpes_2_0_last_modified"
NVD_CPEMATCH_SYNC_ENDPOINT = "nvd_cpematch_2_0_last_modified"
NVD_SOURCE_SYNC_ENDPOINT = "nvd_source_2_0_last_modified"
NVD_CVEHISTORY_SYNC_ENDPOINT = "nvd_cvehistory_2_0_change_modified"
NVD_RESULTS_PER_PAGE = 2000
NVD_CPEMATCH_RESULTS_PER_PAGE = 250
NVD_SOURCE_RESULTS_PER_PAGE = 1000
NVD_REQUEST_DELAY_SECONDS = 6.0
CHECKPOINT_OVERLAP_MINUTES = 5
NVD_MAX_WINDOW_DAYS = 120


def utc_now():
    return datetime.now(timezone.utc)


def parse_timestamp(value):
    text = (value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def to_nvd_timestamp(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def resolve_window(db_path, days=7, use_checkpoint=True):
    return resolve_endpoint_window(db_path, NVD_SYNC_ENDPOINT, days=days, use_checkpoint=use_checkpoint)


def resolve_endpoint_window(db_path, endpoint, days=7, use_checkpoint=True):
    end_at = utc_now()
    checkpoint = get_sync_state(db_path, endpoint) if use_checkpoint else None
    if checkpoint and checkpoint.get("last_end"):
        last_end = parse_timestamp(checkpoint["last_end"])
        if last_end is not None:
            start_at = last_end - timedelta(minutes=CHECKPOINT_OVERLAP_MINUTES)
            if start_at > end_at:
                start_at = end_at - timedelta(minutes=CHECKPOINT_OVERLAP_MINUTES)
            return start_at, end_at, checkpoint
    return end_at - timedelta(days=days), end_at, checkpoint


def split_windows(start_at, end_at, max_days=NVD_MAX_WINDOW_DAYS):
    max_span = timedelta(days=max_days)
    current_start = start_at
    while current_start < end_at:
        current_end = min(current_start + max_span, end_at)
        yield current_start, current_end
        current_start = current_end


def persist_vulnerabilities(db_path, vulnerabilities, api_timestamp):
    saved = 0
    fetched_at = utc_now_text()
    with connect(db_path) as connection:
        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue
            upsert_raw_cve_document(connection, item, api_timestamp=api_timestamp, fetched_at=fetched_at)
            record = parse_nvd_record(item)
            if record:
                upsert_cve(connection, record)
                saved += 1
    return saved


def persist_products(db_path, products, api_timestamp):
    saved = 0
    fetched_at = utc_now_text()
    with connect(db_path) as connection:
        for item in products:
            if not isinstance(item, dict):
                continue
            upsert_raw_cpe_document(connection, item, api_timestamp=api_timestamp, fetched_at=fetched_at)
            record = parse_nvd_cpe_record(item)
            if record:
                upsert_cpe(connection, record)
                saved += 1
    return saved


def persist_match_strings(db_path, match_strings, api_timestamp):
    saved = 0
    fetched_at = utc_now_text()
    with connect(db_path) as connection:
        for item in match_strings:
            if not isinstance(item, dict):
                continue
            upsert_raw_cpematch_document(connection, item, api_timestamp=api_timestamp, fetched_at=fetched_at)
            record = parse_nvd_cpematch_record(item)
            if record:
                upsert_match_string(connection, record)
                saved += 1
    return saved


def persist_sources(db_path, sources, api_timestamp):
    saved = 0
    fetched_at = utc_now_text()
    with connect(db_path) as connection:
        for item in sources:
            if not isinstance(item, dict):
                continue
            upsert_raw_source_document(connection, item, api_timestamp=api_timestamp, fetched_at=fetched_at)
            record = parse_nvd_source_record(item)
            if record:
                upsert_source(connection, record)
                saved += 1
    return saved


def persist_cve_changes(db_path, changes, api_timestamp):
    saved = 0
    fetched_at = utc_now_text()
    with connect(db_path) as connection:
        for item in changes:
            if not isinstance(item, dict):
                continue
            upsert_raw_cvehistory_document(connection, item, api_timestamp=api_timestamp, fetched_at=fetched_at)
            record = parse_nvd_cvehistory_record(item)
            if record:
                upsert_cve_change(connection, record)
                saved += 1
    return saved


def sync_endpoint(
    db_path,
    api_url,
    endpoint,
    result_key,
    persist_fn,
    label,
    api_key="",
    days=7,
    use_checkpoint=True,
    page_size=NVD_RESULTS_PER_PAGE,
    start_param="lastModStartDate",
    end_param="lastModEndDate",
):
    start_at, end_at, checkpoint = resolve_endpoint_window(
        db_path,
        endpoint,
        days=days,
        use_checkpoint=use_checkpoint,
    )
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    processed_total = 0
    saved_total = 0
    request_count = 0

    for window_start, window_end in split_windows(start_at, end_at):
        params = {
            "resultsPerPage": page_size,
            "startIndex": 0,
            start_param: to_nvd_timestamp(window_start),
            end_param: to_nvd_timestamp(window_end),
        }
        processed_window = 0
        total_window = 0

        while True:
            if request_count:
                time.sleep(NVD_REQUEST_DELAY_SECONDS)
            request_count += 1

            response = requests.get(api_url, params=params, headers=headers, timeout=45)
            if response.status_code == 429:
                print("NVD rate limit hit. Waiting before retrying...")
                time.sleep(NVD_REQUEST_DELAY_SECONDS)
                request_count -= 1
                continue
            response.raise_for_status()

            payload = response.json()
            items = payload.get(result_key, [])
            total_window = int(payload.get("totalResults", total_window or 0))
            api_timestamp = payload.get("timestamp")
            saved_total += persist_fn(db_path, items, api_timestamp)
            processed_window += len(items)
            processed_total += len(items)

            print(
                f"Downloaded {processed_window}/{total_window or processed_window} {label} "
                f"for {params[start_param]} -> {params[end_param]}"
            )

            if processed_window >= total_window or not items:
                break

            params["startIndex"] = processed_window

    set_sync_state(
        db_path,
        endpoint,
        last_start=start_at.isoformat(),
        last_end=end_at.isoformat(),
        last_total_results=processed_total,
        last_message=f"Saved {saved_total} {label} records.",
    )

    if checkpoint and checkpoint.get("last_end"):
        print(f"Previous checkpoint: {checkpoint['last_end']}")
    print(f"Saved {saved_total} {label} records from NVD.")
    return saved_total


def sync_recent(db_path, api_key="", days=7, use_checkpoint=True):
    return sync_endpoint(
        db_path=db_path,
        api_url=NVD_API_URL,
        endpoint=NVD_SYNC_ENDPOINT,
        result_key="vulnerabilities",
        persist_fn=persist_vulnerabilities,
        label="CVE",
        api_key=api_key,
        days=days,
        use_checkpoint=use_checkpoint,
        page_size=NVD_RESULTS_PER_PAGE,
        start_param="changeStartDate",
        end_param="changeEndDate",
    )


def sync_cpes(db_path, api_key="", days=7, use_checkpoint=True):
    return sync_endpoint(
        db_path=db_path,
        api_url=NVD_CPE_API_URL,
        endpoint=NVD_CPE_SYNC_ENDPOINT,
        result_key="products",
        persist_fn=persist_products,
        label="CPE",
        api_key=api_key,
        days=days,
        use_checkpoint=use_checkpoint,
        page_size=NVD_RESULTS_PER_PAGE,
    )


def sync_cpematch(db_path, api_key="", days=7, use_checkpoint=True):
    return sync_endpoint(
        db_path=db_path,
        api_url=NVD_CPEMATCH_API_URL,
        endpoint=NVD_CPEMATCH_SYNC_ENDPOINT,
        result_key="matchStrings",
        persist_fn=persist_match_strings,
        label="match-string",
        api_key=api_key,
        days=days,
        use_checkpoint=use_checkpoint,
        page_size=NVD_CPEMATCH_RESULTS_PER_PAGE,
    )


def sync_sources(db_path, api_key="", days=7, use_checkpoint=True):
    return sync_endpoint(
        db_path=db_path,
        api_url=NVD_SOURCE_API_URL,
        endpoint=NVD_SOURCE_SYNC_ENDPOINT,
        result_key="sources",
        persist_fn=persist_sources,
        label="source",
        api_key=api_key,
        days=days,
        use_checkpoint=use_checkpoint,
        page_size=NVD_SOURCE_RESULTS_PER_PAGE,
    )


def sync_cvehistory(db_path, api_key="", days=7, use_checkpoint=True):
    return sync_endpoint(
        db_path=db_path,
        api_url=NVD_CVEHISTORY_API_URL,
        endpoint=NVD_CVEHISTORY_SYNC_ENDPOINT,
        result_key="cveChanges",
        persist_fn=persist_cve_changes,
        label="cve-history",
        api_key=api_key,
        days=days,
        use_checkpoint=use_checkpoint,
        page_size=NVD_RESULTS_PER_PAGE,
        start_param="changeStartDate",
        end_param="changeEndDate",
    )


def run(db_path):
    print("\nNVD sync")
    load_dotenv()
    print("1. Sync CVEs")
    print("2. Sync CPEs")
    print("3. Sync CPE match criteria")
    print("4. Sync sources")
    print("5. Sync CVE history")
    print("6. Sync all")
    choice = input("Choose: ").strip() or "6"
    days_text = input("Fallback window if no checkpoint exists, in days [7]: ").strip() or "7"
    try:
        days = int(days_text)
    except ValueError:
        print("Days must be a whole number.")
        return

    api_key = os.getenv("NIST_API_KEY", "")
    try:
        if choice == "1":
            sync_recent(db_path, api_key=api_key, days=days, use_checkpoint=True)
        elif choice == "2":
            sync_cpes(db_path, api_key=api_key, days=days, use_checkpoint=True)
        elif choice == "3":
            sync_cpematch(db_path, api_key=api_key, days=days, use_checkpoint=True)
        elif choice == "4":
            sync_sources(db_path, api_key=api_key, days=days, use_checkpoint=True)
        elif choice == "5":
            sync_cvehistory(db_path, api_key=api_key, days=days, use_checkpoint=True)
        elif choice == "6":
            sync_recent(db_path, api_key=api_key, days=days, use_checkpoint=True)
            sync_cpes(db_path, api_key=api_key, days=days, use_checkpoint=True)
            sync_cpematch(db_path, api_key=api_key, days=days, use_checkpoint=True)
            sync_sources(db_path, api_key=api_key, days=days, use_checkpoint=True)
            sync_cvehistory(db_path, api_key=api_key, days=days, use_checkpoint=True)
        else:
            print("Invalid choice.")
    except Exception as error:
        print(f"Sync failed: {error}")
