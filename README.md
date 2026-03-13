# Cybersteps CVE DB

Small CLI project for the CVE database assignment.

## Setup

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

## Local Secrets

Create a file named `.env` in the project root, next to `main.py`, and put your keys there. A template is in `.env.example`.
The app loads `.env` via `python-dotenv`.

## Run

```powershell
python main.py
```

## Optional Streamlit UI

```powershell
streamlit run ui.py
```

## Project Layout

- `main.py`: top-level menu
- `db.py`: SQLite connection, schema setup, shared helpers
- `entry.py`: manual entry and lookup by CVE ID
- `imports.py`: file import, stats, and filters
- `sync.py`: NVD sync with `requests`
- `query.py`: AI-generated SQL with a clarification step
- `ui.py`: optional Streamlit frontend with search, filters, charts, and chat
- `schema.sql`: relational schema

## Environment Variables

- `CVE_DB_PATH`: SQLite file path, default `cve.db`
- `NIST_API_KEY`: optional, used for NVD sync
- `CEREBRAS_API_KEY`: optional, primary AI provider for SQL queries
- `CEREBRAS_MODEL`: optional, default `gpt-oss-120b`
- `GEMINI_API_KEY`: optional fallback AI provider for SQL queries
- `GEMINI_MODEL`: optional, default `gemini-2.5-flash`

## CLI Testing

1. Run `python main.py`.
2. Open `Manual entry and lookup`, add one fake CVE, then look it up by the same ID.
3. Open `Import and analysis`, import a small CSV or JSON file, then run `Show stats` and `Filter CVEs`.
4. Open `NVD sync` with `NIST_API_KEY` set if you have one, and sync the last 1-7 days to verify live fetch works.
5. Open `AI query` with `CEREBRAS_API_KEY` or `GEMINI_API_KEY` set and ask something direct like `show CVEs above 9.0`.
6. Check the generated SQL and returned rows each time so you can confirm the CLI behavior, not just that it exits cleanly.

## Notes

- The AI query menu is optional at runtime if you do not have an AI API key.
- AI provider order is Cerebras first, then Gemini fallback.
- The Streamlit UI no longer depends on `pandas`; charts are built from plain Python data.
- The repository may include a prepopulated `cve.db`, so a fresh clone can already contain imported public CVE data.
- Use DB Browser for SQLite to inspect `cve.db` directly.
