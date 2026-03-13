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

## Optional Streamlit UI

```powershell
streamlit run cvedb/ui.py
```

## Project Layout

- `main.py`: top-level menu
- `cvedb/db.py`: SQLite connection, schema setup, shared helpers
- `cvedb/entry.py`: manual entry and lookup by CVE ID
- `cvedb/imports.py`: file import, stats, and filters
- `cvedb/sync.py`: NVD sync with `requests`
- `cvedb/query.py`: AI-generated SQL with a clarification step
- `cvedb/ui.py`: optional Streamlit frontend with search, filters, charts, and chat
- `schema.sql`: relational schema

## Environment Variables

- `CVE_DB_PATH`: SQLite file path, default `cve.db`
- `NIST_API_KEY`: optional, used for NVD sync
- `CEREBRAS_API_KEY`: optional, used for AI queries
- `CEREBRAS_MODEL`: optional, default `gpt-oss-120b`

## CLI Testing

1. Run `python main.py`.
2. Open `Manual entry and lookup`, add one fake CVE, then look it up by the same ID.
3. Open `Import and analysis`, import a small CSV or JSON file, then run `Show stats` and `Filter CVEs`.
4. Open `NVD sync` with `NIST_API_KEY` set if you have one, and sync the last 1-7 days to verify live fetch works.
5. Open `AI query` with `CEREBRAS_API_KEY` set and ask something direct like `show CVEs above 9.0`.
6. Check the generated SQL and returned rows each time so you can confirm the CLI behavior, not just that it exits cleanly.

## Notes

- The AI query menu is optional at runtime if you do not have an AI API key.
- Use DB Browser for SQLite to inspect `cve.db` directly.
