import os
import time
from datetime import date, timedelta

import requests

from cvedb.db import save_records
from cvedb.imports import parse_nvd_record


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def sync_recent(db_path, api_key="", days=7):
    end_date = date.today()
    start_date = end_date - timedelta(days=days)
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "resultsPerPage": 2000,
        "startIndex": 0,
        "lastModStartDate": f"{start_date.isoformat()}T00:00:00.000+00:00",
        "lastModEndDate": f"{end_date.isoformat()}T23:59:59.999+00:00",
    }

    records = []
    processed = 0
    total = 0

    while True:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=45)
        if response.status_code == 429:
            time.sleep(1)
            continue
        response.raise_for_status()

        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities", [])
        total = int(payload.get("totalResults", total or 0))

        for item in vulnerabilities:
            if isinstance(item, dict):
                record = parse_nvd_record(item)
                if record:
                    records.append(record)

        processed += len(vulnerabilities)
        print(f"Downloaded {processed}/{total or processed} records")

        if processed >= total or not vulnerabilities:
            break

        params["startIndex"] = processed
        time.sleep(0.3)

    save_records(db_path, records)
    print(f"Saved {len(records)} records from NVD.")


def run(db_path):
    print("\nNVD sync")
    days_text = input("Sync CVEs updated in the last how many days? [7]: ").strip() or "7"
    try:
        days = int(days_text)
    except ValueError:
        print("Days must be a whole number.")
        return

    api_key = os.getenv("NVD_API_KEY") or input("NVD API key [optional]: ").strip()
    try:
        sync_recent(db_path, api_key=api_key, days=days)
    except Exception as error:
        print(f"Sync failed: {error}")
