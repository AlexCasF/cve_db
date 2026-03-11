import csv, io, json, os, re, sqlite3, time
from datetime import date, datetime, timedelta

import requests
import streamlit as st

SCHEMA = '''
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS vendors(vendor_id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS products(product_id INTEGER PRIMARY KEY, vendor_id INTEGER NOT NULL, name TEXT NOT NULL, UNIQUE(vendor_id,name), FOREIGN KEY(vendor_id) REFERENCES vendors(vendor_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS cves(cve_id TEXT PRIMARY KEY, description TEXT NOT NULL, published TEXT, last_modified TEXT, severity TEXT, cvss_score REAL, source TEXT, url TEXT);
CREATE TABLE IF NOT EXISTS cve_products(cve_id TEXT NOT NULL, product_id INTEGER NOT NULL, PRIMARY KEY(cve_id,product_id), FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE, FOREIGN KEY(product_id) REFERENCES products(product_id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS idx_cvss ON cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_pub ON cves(published);
'''

NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
CEREBRAS_URL = 'https://api.cerebras.ai/v1/chat/completions'
ALLOWED_TABLES = {'cves', 'vendors', 'products', 'cve_products'}


def db(path):
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys = ON')
    return c


def init_db(path):
    with db(path) as c:
        c.executescript(SCHEMA)


def nt(x):
    return '' if x is None else str(x).strip()


def score(x):
    try:
        return None if x in [None, ''] else float(x)
    except Exception:
        return None


def upsert_vendor(c, name):
    name = nt(name) or 'unknown_vendor'
    c.execute('INSERT OR IGNORE INTO vendors(name) VALUES(?)', (name,))
    return c.execute('SELECT vendor_id FROM vendors WHERE name=?', (name,)).fetchone()['vendor_id']


def upsert_product(c, vendor_id, name):
    name = nt(name) or 'unknown_product'
    c.execute('INSERT OR IGNORE INTO products(vendor_id,name) VALUES(?,?)', (vendor_id, name))
    return c.execute('SELECT product_id FROM products WHERE vendor_id=? AND name=?', (vendor_id, name)).fetchone()['product_id']


def upsert_cve(c, r):
    cid = nt(r.get('cve_id'))
    if not cid:
        return
    c.execute('''
    INSERT INTO cves(cve_id,description,published,last_modified,severity,cvss_score,source,url)
    VALUES(?,?,?,?,?,?,?,?)
    ON CONFLICT(cve_id) DO UPDATE SET
      description=excluded.description,published=excluded.published,last_modified=excluded.last_modified,
      severity=excluded.severity,cvss_score=excluded.cvss_score,source=excluded.source,url=excluded.url
    ''', (cid, nt(r.get('description')) or '(no description)', nt(r.get('published')) or None,
          nt(r.get('last_modified')) or None, nt(r.get('severity')), score(r.get('cvss_score')),
          nt(r.get('source')), nt(r.get('url'))))
    c.execute('DELETE FROM cve_products WHERE cve_id=?', (cid,))
    for vendor, product in r.get('affected', []):
        vid = upsert_vendor(c, vendor)
        pid = upsert_product(c, vid, product)
        c.execute('INSERT OR IGNORE INTO cve_products(cve_id,product_id) VALUES(?,?)', (cid, pid))


def save_records(path, recs):
    with db(path) as c:
        for r in recs:
            upsert_cve(c, r)
    return len(recs)


def cpe_pair(uri):
    p = nt(uri).split(':')
    if len(p) >= 6 and p[0] == 'cpe' and p[1] == '2.3':
        v = (p[3] or 'unknown_vendor').replace('_', ' ').lower()
        pr = (p[4] or 'unknown_product').replace('_', ' ').lower()
        return v, pr
    return None


def extract_nvd(v):
    cve = v.get('cve', {})
    cid = nt(cve.get('id'))
    if not cid:
        return None
    desc = ''
    for d in cve.get('descriptions', []):
        if d.get('lang') == 'en':
            desc = nt(d.get('value')); break
    if not desc and cve.get('descriptions'):
        desc = nt(cve['descriptions'][0].get('value'))
    m = cve.get('metrics', {})
    sev, cvss = '', None
    for k in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
        arr = m.get(k, [])
        if arr:
            d = arr[0].get('cvssData', {})
            cvss = score(d.get('baseScore'))
            sev = nt(d.get('baseSeverity') or arr[0].get('baseSeverity'))
            break
    pairs = set()
    for conf in cve.get('configurations', []):
        for node in conf.get('nodes', []):
            stack = [node]
            while stack:
                n = stack.pop()
                for cm in n.get('cpeMatch', []):
                    p = cpe_pair(cm.get('criteria') or cm.get('cpe23Uri'))
                    if p: pairs.add(p)
                stack.extend(n.get('children', []))
    return {
        'cve_id': cid,
        'description': desc,
        'published': nt(cve.get('published')),
        'last_modified': nt(cve.get('lastModified')),
        'severity': sev,
        'cvss_score': cvss,
        'source': 'NVD API',
        'url': f'https://nvd.nist.gov/vuln/detail/{cid}',
        'affected': sorted(pairs),
    }

def parse_json_bytes(b):
    obj = json.loads(b.decode('utf-8', errors='replace'))
    out = []
    if isinstance(obj, dict) and isinstance(obj.get('vulnerabilities'), list):
        for v in obj['vulnerabilities']:
            if isinstance(v, dict):
                r = extract_nvd(v)
                if r: out.append(r)
        return out
    if isinstance(obj, list):
        for it in obj:
            if isinstance(it, dict):
                out.append(parse_generic(it, 'JSON import'))
        return [x for x in out if x]
    if isinstance(obj, dict):
        r = parse_generic(obj, 'JSON import')
        return [r] if r else []
    return []


def parse_csv_bytes(b):
    out = []
    for row in csv.DictReader(io.StringIO(b.decode('utf-8', errors='replace'))):
        r = parse_generic(dict(row), 'CSV import')
        if r: out.append(r)
    return out


def parse_generic(raw, source):
    cid = nt(raw.get('cve_id') or raw.get('id') or raw.get('cve'))
    if not cid:
        return None
    vendors = [x.strip() for x in re.split(r'[;,|]', nt(raw.get('vendor'))) if x.strip()]
    products = [x.strip() for x in re.split(r'[;,|]', nt(raw.get('product'))) if x.strip()]
    aff = []
    if vendors and products:
        for v in vendors:
            for p in products:
                aff.append((v, p))
    elif vendors:
        aff = [(v, 'unknown_product') for v in vendors]
    elif products:
        aff = [('unknown_vendor', p) for p in products]
    return {
        'cve_id': cid,
        'description': nt(raw.get('description') or raw.get('summary')),
        'published': nt(raw.get('published') or raw.get('published_date')),
        'last_modified': nt(raw.get('last_modified') or raw.get('updated') or raw.get('lastModified')),
        'severity': nt(raw.get('severity')),
        'cvss_score': score(raw.get('cvss_score') or raw.get('score') or raw.get('cvss')),
        'source': source,
        'url': nt(raw.get('url')),
        'affected': aff,
    }


def sync_nvd(path, start_d, end_d, api_key='', cb=None):
    headers = {'Accept': 'application/json'}
    if nt(api_key):
        headers['apiKey'] = api_key.strip()
    params = {
        'resultsPerPage': 2000,
        'startIndex': 0,
        'lastModStartDate': f'{start_d.isoformat()}T00:00:00.000+00:00',
        'lastModEndDate': f'{end_d.isoformat()}T23:59:59.999+00:00',
    }
    total, done, upserted = 0, 0, 0
    with db(path) as c:
        while True:
            r = requests.get(NVD_URL, params=params, headers=headers, timeout=45)
            if r.status_code == 429:
                time.sleep(1.2); continue
            r.raise_for_status()
            j = r.json(); vulns = j.get('vulnerabilities', [])
            total = int(j.get('totalResults', total or 0))
            if total == 0 and not vulns:
                break
            for v in vulns:
                rec = extract_nvd(v)
                if rec:
                    upsert_cve(c, rec); upserted += 1
            done += len(vulns)
            if cb: cb(min(done, total), max(total, 1))
            if done >= total or not vulns:
                break
            params['startIndex'] = done
            time.sleep(0.35)
    return upserted, total


def qrows(path, sql, p=()):
    with db(path) as c:
        return [dict(x) for x in c.execute(sql, p).fetchall()]


def qone(path, sql, p=()):
    r = qrows(path, sql, p)
    return r[0] if r else None


def top_vendors(path):
    return qrows(path, '''
    SELECT v.name vendor, COUNT(DISTINCT cp.cve_id) vuln_count
    FROM vendors v LEFT JOIN products p ON p.vendor_id=v.vendor_id
    LEFT JOIN cve_products cp ON cp.product_id=p.product_id
    GROUP BY v.vendor_id ORDER BY vuln_count DESC, v.name LIMIT 10''')


def severity_counts(path):
    return qrows(path, """
    SELECT COALESCE(NULLIF(TRIM(severity),''),'UNKNOWN') severity, COUNT(*) count
    FROM cves GROUP BY COALESCE(NULLIF(TRIM(severity),''),'UNKNOWN') ORDER BY count DESC
    """)


def filter_cves(path, keyword='', min_cvss=0.0, max_cvss=10.0, vendor='', limit=100):
    where, p = ['1=1', '(c.cvss_score IS NULL OR c.cvss_score BETWEEN ? AND ?)'], [float(min_cvss), float(max_cvss)]
    if nt(keyword):
        where.append('(LOWER(c.cve_id) LIKE ? OR LOWER(c.description) LIKE ?)')
        kw = f"%{keyword.lower().strip()}%"; p += [kw, kw]
    if nt(vendor):
        where.append('LOWER(v.name)=?'); p.append(vendor.lower().strip())
    p.append(int(limit))
    sql = f"""
    SELECT c.cve_id,c.published,c.cvss_score,c.severity,c.description,
           GROUP_CONCAT(DISTINCT v.name) vendors, GROUP_CONCAT(DISTINCT p.name) products
    FROM cves c
    LEFT JOIN cve_products cp ON cp.cve_id=c.cve_id
    LEFT JOIN products p ON p.product_id=cp.product_id
    LEFT JOIN vendors v ON v.vendor_id=p.vendor_id
    WHERE {' AND '.join(where)}
    GROUP BY c.cve_id
    ORDER BY (c.cvss_score IS NULL), c.cvss_score DESC, c.published DESC
    LIMIT ?
    """
    return qrows(path, sql, p)


def clarifier(text):
    t = text.lower()
    has_num = re.search(r'\b\d+(\.\d+)?\b', t)
    has_date = re.search(r'\b(last|this|today|yesterday|\d{4}-\d{2}-\d{2})\b', t)
    if ('bad' in t or 'serious' in t) and not has_num:
        return 'What CVSS threshold should I use for bad (example 7.0 or 9.0)?'
    if ('recent' in t or 'latest' in t or 'new' in t) and not has_date:
        return 'What date range do you mean (example last 30 days)?'
    return None


def extract_sql(txt):
    m = re.search(r'```(?:sql)?\s*(.*?)```', txt, re.I | re.S)
    if m: txt = m.group(1)
    m = re.search(r'\bselect\b.*', txt, re.I | re.S)
    if m: txt = m.group(0)
    txt = txt.strip().rstrip(';')
    return txt.split(';', 1)[0].strip()


def safe_sql(sql):
    s = nt(sql).strip().rstrip(';')
    if not s.lower().startswith('select'):
        raise ValueError('Only SELECT allowed')
    if re.search(r'\b(insert|update|delete|drop|alter|create|attach|pragma|vacuum|reindex|truncate|replace)\b', s, re.I):
        raise ValueError('Unsafe SQL blocked')
    for t in re.findall(r'\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_]*)', s, re.I):
        if t.lower() not in ALLOWED_TABLES:
            raise ValueError(f'Table not allowed: {t}')
    if ' limit ' not in s.lower():
        s += ' LIMIT 200'
    return s


def llm_sql(question, api_key, model):
    schema = (
        'cves(cve_id,description,published,last_modified,severity,cvss_score,source,url)\n'
        'vendors(vendor_id,name)\nproducts(product_id,vendor_id,name)\n'
        'cve_products(cve_id,product_id)'
    )
    sys = (
        'Return exactly one SQLite SELECT query only. '
        'Use only listed tables/columns. Never use mutating SQL.'
    )
    user = f'Schema:\n{schema}\nUser request: {question}\nReturn SQL only.'
    r = requests.post(CEREBRAS_URL, headers={
        'Authorization': f'Bearer {api_key.strip()}', 'Content-Type': 'application/json'
    }, json={
        'model': model.strip(), 'temperature': 0.1, 'max_tokens': 350,
        'messages': [{'role': 'system', 'content': sys}, {'role': 'user', 'content': user}]
    }, timeout=60)
    r.raise_for_status()
    j = r.json(); ch = j.get('choices', [])
    if not ch:
        raise RuntimeError('No model output')
    return ch[0].get('message', {}).get('content', '')


def md_table(rows, n=12):
    if not rows:
        return '_No rows returned._'
    rows = rows[:n]
    h = list(rows[0].keys())
    out = ['| ' + ' | '.join(h) + ' |', '| ' + ' | '.join(['---'] * len(h)) + ' |']
    for r in rows:
        out.append('| ' + ' | '.join(str(r.get(k, '')).replace('\n', ' ') for k in h) + ' |')
    return '\n'.join(out)

def relation_dot(cve_id, rel):
    esc = lambda x: str(x).replace('"', "'")
    lines = ['digraph G {', 'rankdir=LR;', f'"{esc(cve_id)}" [shape=ellipse, style=filled, fillcolor="#FFEAA7"];']
    for r in rel:
        v = f"Vendor: {esc(r.get('vendor', 'unknown_vendor'))}"
        p = f"Product: {esc(r.get('product', 'unknown_product'))}"
        lines.append(f'"{v}" [shape=box, style=filled, fillcolor="#D6EAF8"];')
        lines.append(f'"{p}" [shape=box, style=filled, fillcolor="#D5F5E3"];')
        lines.append(f'"{esc(cve_id)}" -> "{p}";')
        lines.append(f'"{v}" -> "{p}";')
    lines.append('}')
    return '\n'.join(lines)


def page_foundations(path):
    st.subheader('Manual Entry')
    with st.form('manual'):
        cve_id = st.text_input('CVE ID', placeholder='CVE-2026-12345')
        desc = st.text_area('Description', height=110)
        pub = st.date_input('Published date', value=date.today())
        sev = st.selectbox('Severity', ['', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
        cvss = st.number_input('CVSS score', min_value=0.0, max_value=10.0, value=0.0, step=0.1)
        vendor = st.text_input('Vendor', placeholder='microsoft')
        product = st.text_input('Product', placeholder='windows_11')
        go = st.form_submit_button('Save CVE')
    if go:
        if not nt(cve_id):
            st.error('CVE ID is required.')
        else:
            rec = {
                'cve_id': cve_id.strip(), 'description': desc.strip(),
                'published': f'{pub.isoformat()}T00:00:00',
                'last_modified': datetime.utcnow().replace(microsecond=0).isoformat(),
                'severity': sev, 'cvss_score': cvss, 'source': 'manual',
                'url': f'https://nvd.nist.gov/vuln/detail/{cve_id.strip()}',
                'affected': [(vendor.strip(), product.strip())] if vendor.strip() and product.strip() else [],
            }
            save_records(path, [rec]); st.success(f"Saved {rec['cve_id']}")

    st.divider(); st.subheader('Lookup by CVE ID')
    lookup = st.text_input('Find CVE', placeholder='CVE-2024-3094')
    if st.button('Lookup'):
        row = qone(path, 'SELECT * FROM cves WHERE cve_id=?', (lookup.strip(),))
        rel = qrows(path, '''
            SELECT v.name vendor,p.name product FROM cve_products cp
            JOIN products p ON p.product_id=cp.product_id
            JOIN vendors v ON v.vendor_id=p.vendor_id
            WHERE cp.cve_id=? ORDER BY v.name,p.name''', (lookup.strip(),))
        if row:
            st.write(row)
            st.dataframe(rel, use_container_width=True) if rel else st.info('No linked products/vendors.')
        else:
            st.warning('No match found.')


def page_import_sync(path, nvd_key):
    st.subheader('Bulk Import')
    up = st.file_uploader('Upload CSV or JSON', type=['csv', 'json'])
    if st.button('Import Uploaded File', disabled=up is None):
        try:
            recs = parse_json_bytes(up.getvalue()) if up.name.lower().endswith('.json') else parse_csv_bytes(up.getvalue())
            st.success(f'Imported {save_records(path, recs)} records from {up.name}')
        except Exception as e:
            st.error(f'Import failed: {e}')

    st.divider(); st.subheader('Live Sync From NVD')
    c1, c2 = st.columns(2)
    with c1: start_d = st.date_input('Last modified start', value=date.today() - timedelta(days=7))
    with c2: end_d = st.date_input('Last modified end', value=date.today())
    if st.button('Sync NVD'):
        if start_d > end_d:
            st.error('Start date must be before end date.')
            return
        bar, note = st.progress(0), st.empty()
        def cb(done, total):
            bar.progress(min(100, int(done * 100 / max(1, total))))
            note.write(f'Processed {done}/{total}')
        try:
            upserted, total = sync_nvd(path, start_d, end_d, nvd_key, cb)
            bar.progress(100); note.write(f'Processed {total}/{total}')
            st.success(f'NVD sync complete. Upserted {upserted} CVEs.')
        except Exception as e:
            st.error(f'NVD sync failed: {e}')


def page_explore(path):
    st.subheader('Analytics')
    s = qone(path, 'SELECT COUNT(*) total_cves, ROUND(AVG(cvss_score),2) avg_cvss, SUM(CASE WHEN cvss_score>=9 THEN 1 ELSE 0 END) critical_like FROM cves') or {}
    c1, c2, c3 = st.columns(3)
    c1.metric('Total CVEs', int(s.get('total_cves') or 0))
    c2.metric('Average CVSS', 'N/A' if s.get('avg_cvss') is None else str(s.get('avg_cvss')))
    c3.metric('CVSS >= 9.0', int(s.get('critical_like') or 0))

    a, b = st.columns(2)
    with a:
        st.markdown('**Top vendors by CVE count**'); st.dataframe(top_vendors(path), use_container_width=True)
    with b:
        st.markdown('**Severity distribution**'); st.dataframe(severity_counts(path), use_container_width=True)

    st.divider(); st.subheader('Smart Filters')
    f1, f2, f3, f4 = st.columns([2, 1, 1, 1])
    with f1: kw = st.text_input('Keyword in ID or description', value='')
    with f2: mn = st.number_input('Min CVSS', 0.0, 10.0, 0.0, 0.1)
    with f3: mx = st.number_input('Max CVSS', 0.0, 10.0, 10.0, 0.1)
    with f4: lim = st.number_input('Max rows', 10, 1000, 100, 10)
    vendors = [''] + [r['name'] for r in qrows(path, 'SELECT name FROM vendors ORDER BY name')]
    vend = st.selectbox('Vendor filter (optional)', vendors)
    if st.button('Run Filter Query'):
        rows = filter_cves(path, kw, mn, mx, vend, lim)
        st.write(f'Returned {len(rows)} rows.'); st.dataframe(rows, use_container_width=True)

    st.divider(); st.subheader('CVE Relationship View')
    cves = [r['cve_id'] for r in qrows(path, 'SELECT cve_id FROM cves ORDER BY published DESC, cve_id DESC LIMIT 300')]
    if not cves:
        st.info('No CVEs in DB yet. Import or add records first.'); return
    cid = st.selectbox('Pick CVE', cves)
    row = qone(path, 'SELECT * FROM cves WHERE cve_id=?', (cid,))
    rel = qrows(path, '''
      SELECT v.name vendor,p.name product FROM cve_products cp
      JOIN products p ON p.product_id=cp.product_id
      JOIN vendors v ON v.vendor_id=p.vendor_id
      WHERE cp.cve_id=? ORDER BY v.name,p.name''', (cid,))
    if row:
        st.caption(f"{row.get('severity','')} | CVSS {row.get('cvss_score','')}")
        st.write(row.get('description', ''))
    if rel:
        dot = relation_dot(cid, rel)
        try: st.graphviz_chart(dot, use_container_width=True)
        except Exception: st.dataframe(rel, use_container_width=True)
    else:
        st.info('No product/vendor relationships mapped for this CVE.')


def page_ai(path, ckey, model):
    st.subheader('Ask In Natural Language (AI -> SQL)')
    st.caption('Generates read-only SQL with Cerebras, validates, then runs it on SQLite.')
    if 'chat' not in st.session_state: st.session_state.chat = []
    if 'pending' not in st.session_state: st.session_state.pending = None
    for m in st.session_state.chat:
        with st.chat_message(m['role']): st.markdown(m['content'])
    prompt = st.chat_input('Example: Show Microsoft vulnerabilities from last month above 8.0')
    if not prompt: return
    st.session_state.chat.append({'role': 'user', 'content': prompt})
    eff = prompt
    if st.session_state.pending:
        eff = f"{st.session_state.pending}\nClarification: {prompt}"; st.session_state.pending = None
    else:
        q = clarifier(prompt)
        if q:
            st.session_state.pending = prompt
            st.session_state.chat.append({'role': 'assistant', 'content': q})
            st.rerun()
    try:
        raw = llm_sql(eff, ckey, model)
        sql = safe_sql(extract_sql(raw))
        rows = qrows(path, sql)
        ans = f"```sql\n{sql}\n```\n\nReturned {len(rows)} row(s).\n\n{md_table(rows)}"
    except Exception as e:
        ans = f'Could not run AI query: {e}'
    st.session_state.chat.append({'role': 'assistant', 'content': ans}); st.rerun()


def main():
    st.set_page_config(page_title='Cybersteps CVE DB', layout='wide')
    st.title('Cybersteps CVE DB')
    st.caption('Single-file Streamlit + SQLite CVE database with import, sync, filters, and AI SQL.')

    path = st.sidebar.text_input('SQLite DB file', value=os.getenv('CVE_DB_PATH', 'cve.db'))
    nvd_key = st.sidebar.text_input('NVD API key (optional)', value=os.getenv('NVD_API_KEY', ''), type='password')
    ckey = st.sidebar.text_input('Cerebras API key', value=os.getenv('CEREBRAS_API_KEY', ''), type='password')
    model = st.sidebar.text_input('Cerebras model', value=os.getenv('CEREBRAS_MODEL', 'llama-4-scout-17b-16e-instruct'))

    init_db(path); st.sidebar.success(f'DB ready: {path}')
    with st.sidebar.expander('Schema (copy for submission)'):
        st.code(SCHEMA.strip(), language='sql')

    t1, t2, t3, t4 = st.tabs(['1) Foundations', '2) Import + Live Sync', '3) Explore + Relations', '4) AI Chat SQL'])
    with t1: page_foundations(path)
    with t2: page_import_sync(path, nvd_key)
    with t3: page_explore(path)
    with t4: page_ai(path, ckey, model)


if __name__ == '__main__':
    main()
