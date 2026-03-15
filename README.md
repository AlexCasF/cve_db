# Cybersteps CVE DB

Cybersteps CVE DB is a Python + SQLite project for storing, exploring, syncing, and querying CVE-style vulnerability data. It includes a terminal menu for the assignment requirements, a relational schema with normalized vendor/product relationships, a bulk import pipeline for CSV and JSON, live NVD sync, and an optional AI-powered natural-language-to-SQL feature.


## What This Project Does
- Manually add a CVE and look it up by ID
- Import CVEs from CSV or JSON files
- Parse official NVD-style JSON vulnerability feeds
- Analyze the dataset with stats and filters
- Sync recently updated CVEs from the NVD API
- Ask questions in plain English and have AI generate safe SQL
- Browse the same database through an optional Streamlit UI

## Tech Stack

- Python
- SQLite
- `sqlite3`
- `requests`
- `python-dotenv`
- `streamlit`
- Cerebras API or Google Gemini API for AI query generation

## Project Structure

- `main.py` - CLI entry point and top-level menu
- `db.py` - database connection, schema initialization, upsert helpers, row formatting
- `entry.py` - manual CVE entry and lookup by CVE ID
- `imports.py` - CSV/JSON import, NVD JSON parsing, stats, and filtering
- `sync.py` - live NVD sync using `requests`
- `query.py` - AI planning, SQL validation, clarification loop, metering
- `ui.py` - optional Streamlit frontend
- `schema.sql` - relational schema and indexes
- `cve.db` - SQLite database file used by default

## Database Design

The schema is normalized into four tables:

- `cves` stores the main vulnerability record
- `vendors` stores vendor names
- `products` stores products and links them to a vendor
- `cve_products` is the many-to-many bridge between CVEs and products

This structure keeps the core CVE data simple while still supporting questions like:

- Which vendor has the most CVEs?
- Which products are affected by a specific CVE?
- Show me recent high-severity issues for a certain company

## Setup

Create and activate a virtual environment, then install dependencies:

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

## Environment Variables

Create a `.env` file in the project root. You can copy from `.env.example`.

```env
CVE_DB_PATH=cve.db
NIST_API_KEY=your_nist_key_here
CEREBRAS_API_KEY=your_cerebras_key_here
CEREBRAS_MODEL=qwen-3-235b-a22b-instruct-2507
GEMINI_API_KEY=your_gemini_key_here
GEMINI_MODEL=gemini-2.5-flash
```

Notes:

- `CVE_DB_PATH` is optional. If omitted, the app uses `cve.db`.
- `NIST_API_KEY` is optional but recommended for NVD sync.
- `CEREBRAS_API_KEY` and `GEMINI_API_KEY` are optional unless you want AI query/chat.
- `CEREBRAS_MODEL` defaults to `qwen-3-235b-a22b-instruct-2507`.
- AI query works with either provider. Cerebras is preferred if configured.

## Run The CLI

```powershell
python main.py
```

CLI menu:

1. Manual entry and lookup
2. Import and analysis
3. NVD sync
4. AI query
0. Exit

## Run The Streamlit UI

```powershell
streamlit run ui.py
```

The UI has four tabs:

- Search
- Data
- Analytics
- Chat

## How Each Part Works

### 1. Manual Entry and Lookup

`entry.py` lets you:

- add a CVE manually
- attach one optional vendor/product pair
- search by exact CVE ID

Manual entries are saved through shared upsert logic in `db.py`.

### 2. Import and Analysis

`imports.py` supports:

- CSV imports using `csv.DictReader`
- generic JSON object/list imports
- official NVD-style JSON files with a top-level `vulnerabilities` array

It also provides:

- total CVE count
- average CVSS
- top vendors by vulnerability count
- keyword and minimum-CVSS filtering

Accepted import formats:

- `.csv`
- `.json`

### 3. NVD Sync

`sync.py` fetches recently modified CVEs from:

- `https://services.nvd.nist.gov/rest/json/cves/2.0`

It:

- requests CVEs for the last `N` days
- paginates through results
- parses each NVD item into the local schema
- upserts everything into SQLite

## 4. AI Query

`query.py` turns natural language into validated SQLite `SELECT` statements.

The flow is:

1. The user asks a question such as `show me microsoft issues above 8.0`
2. The model returns either:
   - a clarification question, or
   - a SQL query plan in JSON
3. The SQL is sanitized and restricted to allowed tables
4. SQLite validates the query with `EXPLAIN QUERY PLAN`
5. The query runs and the results are shown

Safety rules in the code:

- only `SELECT` queries are allowed
- destructive SQL is blocked
- only known tables are allowed
- a default `LIMIT` is added if missing

The AI layer also includes:

- provider selection
- simple rate limiting per provider
- retry support for invalid query plans
- request/token metrics
- a fallback path for Cerebras model compatibility issues

## Quick Demo Checklist

1. Run `python main.py`
2. Add one fake CVE in `Manual entry and lookup`
3. Look up the same CVE by ID
4. Import a small CSV or JSON file in `Import and analysis`
5. Run `Show stats`
6. Run `Filter CVEs`
7. Try `NVD sync` for the last 1 to 7 days
8. Try `AI query` if you configured an API key

## Notes

- The database schema is initialized automatically on startup.
- If `cve.db` already exists, the project will reuse it.
- The repository may already contain a populated `cve.db`.
- The Streamlit frontend uses the same database file as the CLI.
- Use DB Browser for SQLite if you want to inspect the database directly.

## Submission Helper

The file `pdf.html` is included as a printable project summary for submission item 4, "Project Summary (PDF)".

To convert it to a PDF:

1. Open `pdf.html` in a browser
2. Press Print
3. Choose `Save as PDF`
