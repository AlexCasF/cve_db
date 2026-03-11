# Cybersteps CVE DB

Single-file Streamlit app for a relational CVE database.

## Quick Start

1. Create and activate a virtual environment.
2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Run the app:

```powershell
streamlit run app.py
```

## Optional Env Vars

- `CVE_DB_PATH` (default: `cve.db`)
- `NVD_API_KEY`
- `CEREBRAS_API_KEY`
- `CEREBRAS_MODEL` (default in app sidebar)

## What This MVP Includes

- SQLite schema and auto-init
- Manual CVE entry + lookup by CVE ID
- Bulk import from CSV/JSON
- NVD API sync by date range
- SQL analytics + filters
- CVE relation visualization (vendor/product)
- Natural language to SQL (Cerebras), with read-only SQL safety checks

- schema.sql contains the same relational schema used by the app.
