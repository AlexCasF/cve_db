# Cybersteps CVE DB

Small CLI project for the CVE database assignment.

## Setup

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```powershell
python main.py
```

## Project Layout

- `main.py`: top-level menu
- `cvedb/db.py`: SQLite connection, schema setup, shared helpers
- `cvedb/entry.py`: manual entry and lookup by CVE ID
- `cvedb/imports.py`: file import, stats, and filters
- `cvedb/sync.py`: NVD sync with `requests`
- `cvedb/query.py`: AI-generated SQL with a clarification step
- `schema.sql`: relational schema

## Environment Variables

- `CVE_DB_PATH`: SQLite file path, default `cve.db`
- `NVD_API_KEY`: optional, used for NVD sync
- `CEREBRAS_API_KEY`: optional, used for AI queries
- `CEREBRAS_MODEL`: optional, default `llama-4-scout-17b-16e-instruct`

## Notes

- The AI query menu is optional at runtime if you do not have an AI API key.
- Use DB Browser for SQLite to inspect `cve.db` directly.
