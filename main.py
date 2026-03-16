import os

from db import init_db
from entry import run as run_entry
from imports import run as run_imports
from query import run as run_query, run_sql_console
from sync import run as run_sync
from dotenv import load_dotenv


def main():
    load_dotenv()
    db_path = os.getenv("CVE_DB_PATH", "cve.db")
    init_db(db_path)

    while True:
        print("\nCybersteps CVE DB")
        print(f"Database: {db_path}")
        print("1. Manual entry and lookup")
        print("2. Import and analysis")
        print("3. NVD sync")
        print("4. AI query")
        print("5. Manual SQL")
        print("0. Exit")
        choice = input("Choose: ").strip()

        if choice == "1":
            run_entry(db_path)
        elif choice == "2":
            run_imports(db_path)
        elif choice == "3":
            run_sync(db_path)
        elif choice == "4":
            run_query(db_path)
        elif choice == "5":
            run_sql_console(db_path)
        elif choice == "0":
            return
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
