from datetime import date

from cvedb.db import fetch_all, fetch_one, print_rows, save_records


def add_cve(db_path):
    print("\nAdd a CVE")
    cve_id = input("CVE ID: ").strip()
    if not cve_id:
        print("CVE ID is required.")
        return

    published = input(f"Published date [{date.today().isoformat()}]: ").strip() or date.today().isoformat()
    vendor = input("Vendor [optional]: ").strip()
    product = input("Product [optional]: ").strip()

    save_records(
        db_path,
        [
            {
                "cve_id": cve_id,
                "description": input("Description: ").strip(),
                "published": published,
                "last_modified": published,
                "severity": input("Severity [optional]: ").strip().upper(),
                "cvss_score": input("CVSS score [optional]: ").strip(),
                "source": "manual",
                "url": "",
                "affected": [(vendor, product)] if vendor and product else [],
            }
        ],
    )
    print(f"Saved {cve_id}.")


def find_cve(db_path):
    cve_id = input("\nEnter CVE ID: ").strip()
    if not cve_id:
        print("CVE ID is required.")
        return

    cve = fetch_one(db_path, "SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
    if not cve:
        print("No matching CVE found.")
        return

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
        (cve_id,),
    )

    print()
    print_rows([cve], limit=1)
    if related:
        print("\nAffected products")
        print_rows(related)


def run(db_path):
    while True:
        print("\nManual entry and lookup")
        print("1. Add CVE")
        print("2. Find CVE by ID")
        print("0. Back")
        choice = input("Choose: ").strip()

        if choice == "1":
            add_cve(db_path)
        elif choice == "2":
            find_cve(db_path)
        elif choice == "0":
            return
        else:
            print("Invalid choice.")
