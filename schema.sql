PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS vendors(
    vendor_id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS products(
    product_id INTEGER PRIMARY KEY,
    vendor_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    UNIQUE(vendor_id, name),
    FOREIGN KEY(vendor_id) REFERENCES vendors(vendor_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cves(
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    published TEXT,
    last_modified TEXT,
    severity TEXT,
    cvss_score REAL,
    source TEXT,
    url TEXT
);

CREATE TABLE IF NOT EXISTS cve_products(
    cve_id TEXT NOT NULL,
    product_id INTEGER NOT NULL,
    PRIMARY KEY(cve_id, product_id),
    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
    FOREIGN KEY(product_id) REFERENCES products(product_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cvss ON cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_pub ON cves(published);
