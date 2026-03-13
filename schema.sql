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
    source_identifier TEXT,
    vuln_status TEXT,
    published TEXT,
    last_modified TEXT,
    evaluator_comment TEXT,
    evaluator_impact TEXT,
    evaluator_solution TEXT,
    cisa_exploit_add TEXT,
    cisa_action_due TEXT,
    cisa_required_action TEXT,
    cisa_vulnerability_name TEXT,
    description TEXT NOT NULL,
    severity TEXT,
    cvss_score REAL,
    source TEXT,
    url TEXT,
    raw_json TEXT
);

CREATE TABLE IF NOT EXISTS raw_cve_documents(
    cve_id TEXT PRIMARY KEY,
    published TEXT,
    last_modified TEXT,
    api_timestamp TEXT,
    fetched_at TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_cpe_documents(
    cpe_name_id TEXT PRIMARY KEY,
    cpe_name TEXT NOT NULL,
    created TEXT,
    last_modified TEXT,
    deprecated INTEGER NOT NULL DEFAULT 0,
    api_timestamp TEXT,
    fetched_at TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_cpematch_documents(
    match_criteria_id TEXT PRIMARY KEY,
    criteria TEXT NOT NULL,
    created TEXT,
    last_modified TEXT,
    status TEXT,
    api_timestamp TEXT,
    fetched_at TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_source_documents(
    source_name TEXT PRIMARY KEY,
    contact_email TEXT,
    created TEXT,
    last_modified TEXT,
    api_timestamp TEXT,
    fetched_at TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_cvehistory_documents(
    cve_change_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL,
    event_name TEXT,
    source_identifier TEXT,
    created TEXT,
    api_timestamp TEXT,
    fetched_at TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_state(
    endpoint TEXT PRIMARY KEY,
    last_start TEXT,
    last_end TEXT,
    last_success_at TEXT,
    last_total_results INTEGER,
    last_message TEXT
);

CREATE TABLE IF NOT EXISTS cve_products(
    cve_id TEXT NOT NULL,
    product_id INTEGER NOT NULL,
    PRIMARY KEY(cve_id, product_id),
    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE,
    FOREIGN KEY(product_id) REFERENCES products(product_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS nvd_cpes(
    cpe_name_id TEXT PRIMARY KEY,
    cpe_name TEXT NOT NULL,
    part TEXT,
    vendor TEXT,
    product TEXT,
    version TEXT,
    update_value TEXT,
    edition TEXT,
    language TEXT,
    sw_edition TEXT,
    target_sw TEXT,
    target_hw TEXT,
    other_value TEXT,
    created TEXT,
    last_modified TEXT,
    deprecated INTEGER NOT NULL DEFAULT 0,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nvd_cpe_titles(
    cpe_name_id TEXT NOT NULL,
    lang TEXT NOT NULL,
    title TEXT NOT NULL,
    PRIMARY KEY(cpe_name_id, lang, title),
    FOREIGN KEY(cpe_name_id) REFERENCES nvd_cpes(cpe_name_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS nvd_cpe_refs(
    cpe_name_id TEXT NOT NULL,
    ref_index INTEGER NOT NULL,
    ref TEXT NOT NULL,
    type TEXT,
    PRIMARY KEY(cpe_name_id, ref_index),
    FOREIGN KEY(cpe_name_id) REFERENCES nvd_cpes(cpe_name_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS nvd_cpe_deprecates(
    cpe_name_id TEXT NOT NULL,
    related_cpe_name_id TEXT,
    related_cpe_name TEXT NOT NULL,
    PRIMARY KEY(cpe_name_id, related_cpe_name),
    FOREIGN KEY(cpe_name_id) REFERENCES nvd_cpes(cpe_name_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS nvd_cpe_deprecated_by(
    cpe_name_id TEXT NOT NULL,
    related_cpe_name_id TEXT,
    related_cpe_name TEXT NOT NULL,
    PRIMARY KEY(cpe_name_id, related_cpe_name),
    FOREIGN KEY(cpe_name_id) REFERENCES nvd_cpes(cpe_name_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS nvd_match_strings(
    match_criteria_id TEXT PRIMARY KEY,
    criteria TEXT NOT NULL,
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including TEXT,
    version_end_excluding TEXT,
    created TEXT,
    last_modified TEXT,
    cpe_last_modified TEXT,
    status TEXT,
    matches_count INTEGER NOT NULL DEFAULT 0,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nvd_match_string_matches(
    match_criteria_id TEXT NOT NULL,
    cpe_name_id TEXT,
    cpe_name TEXT NOT NULL,
    PRIMARY KEY(match_criteria_id, cpe_name),
    FOREIGN KEY(match_criteria_id) REFERENCES nvd_match_strings(match_criteria_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS nvd_sources(
    source_name TEXT PRIMARY KEY,
    contact_email TEXT,
    created TEXT,
    last_modified TEXT,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nvd_source_identifiers(
    source_name TEXT NOT NULL,
    source_identifier TEXT NOT NULL,
    PRIMARY KEY(source_name, source_identifier),
    FOREIGN KEY(source_name) REFERENCES nvd_sources(source_name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS nvd_source_acceptance_levels(
    source_name TEXT NOT NULL,
    level_type TEXT NOT NULL,
    description TEXT,
    last_modified TEXT,
    PRIMARY KEY(source_name, level_type),
    FOREIGN KEY(source_name) REFERENCES nvd_sources(source_name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS nvd_cve_changes(
    cve_change_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL,
    event_name TEXT,
    source_identifier TEXT,
    created TEXT,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nvd_cve_change_details(
    cve_change_id TEXT NOT NULL,
    detail_index INTEGER NOT NULL,
    action TEXT,
    type TEXT,
    old_value TEXT,
    new_value TEXT,
    PRIMARY KEY(cve_change_id, detail_index),
    FOREIGN KEY(cve_change_id) REFERENCES nvd_cve_changes(cve_change_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_tags(
    cve_id TEXT NOT NULL,
    source_identifier TEXT,
    tag TEXT NOT NULL,
    PRIMARY KEY(cve_id, source_identifier, tag),
    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_descriptions(
    cve_id TEXT NOT NULL,
    lang TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY(cve_id, lang, value),
    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_metrics(
    metric_id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL,
    metric_key TEXT NOT NULL,
    metric_index INTEGER NOT NULL,
    source TEXT,
    type TEXT,
    version TEXT,
    vector_string TEXT,
    base_severity TEXT,
    base_score REAL,
    exploitability_score REAL,
    impact_score REAL,
    data_json TEXT NOT NULL,
    UNIQUE(cve_id, metric_key, metric_index),
    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_weaknesses(
    weakness_id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL,
    weakness_index INTEGER NOT NULL,
    source TEXT,
    type TEXT,
    UNIQUE(cve_id, weakness_index),
    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_weakness_descriptions(
    weakness_id INTEGER NOT NULL,
    lang TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY(weakness_id, lang, value),
    FOREIGN KEY(weakness_id) REFERENCES cve_weaknesses(weakness_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_references(
    reference_id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL,
    reference_index INTEGER NOT NULL,
    url TEXT NOT NULL,
    source TEXT,
    UNIQUE(cve_id, reference_index),
    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_reference_tags(
    reference_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    PRIMARY KEY(reference_id, tag),
    FOREIGN KEY(reference_id) REFERENCES cve_references(reference_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_configurations(
    configuration_id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL,
    configuration_index INTEGER NOT NULL,
    UNIQUE(cve_id, configuration_index),
    FOREIGN KEY(cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_nodes(
    node_id INTEGER PRIMARY KEY,
    configuration_id INTEGER NOT NULL,
    parent_node_id INTEGER,
    node_index INTEGER NOT NULL,
    operator TEXT,
    negate INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(configuration_id) REFERENCES cve_configurations(configuration_id) ON DELETE CASCADE,
    FOREIGN KEY(parent_node_id) REFERENCES cve_nodes(node_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_matches(
    match_id INTEGER PRIMARY KEY,
    node_id INTEGER NOT NULL,
    match_index INTEGER NOT NULL,
    vulnerable INTEGER NOT NULL DEFAULT 0,
    criteria TEXT NOT NULL,
    match_criteria_id TEXT,
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including TEXT,
    version_end_excluding TEXT,
    UNIQUE(node_id, match_index),
    FOREIGN KEY(node_id) REFERENCES cve_nodes(node_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_match_names(
    match_id INTEGER NOT NULL,
    cpe_name TEXT NOT NULL,
    cpe_name_id TEXT,
    PRIMARY KEY(match_id, cpe_name, cpe_name_id),
    FOREIGN KEY(match_id) REFERENCES cve_matches(match_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cvss ON cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_pub ON cves(published);
CREATE INDEX IF NOT EXISTS idx_raw_cve_last_modified ON raw_cve_documents(last_modified);
CREATE INDEX IF NOT EXISTS idx_raw_cve_fetched_at ON raw_cve_documents(fetched_at);
CREATE INDEX IF NOT EXISTS idx_raw_cpe_last_modified ON raw_cpe_documents(last_modified);
CREATE INDEX IF NOT EXISTS idx_raw_cpe_cpe_name ON raw_cpe_documents(cpe_name);
CREATE INDEX IF NOT EXISTS idx_raw_cpematch_last_modified ON raw_cpematch_documents(last_modified);
CREATE INDEX IF NOT EXISTS idx_raw_cpematch_criteria ON raw_cpematch_documents(criteria);
CREATE INDEX IF NOT EXISTS idx_raw_source_last_modified ON raw_source_documents(last_modified);
CREATE INDEX IF NOT EXISTS idx_raw_source_contact ON raw_source_documents(contact_email);
CREATE INDEX IF NOT EXISTS idx_raw_cvehistory_created ON raw_cvehistory_documents(created);
CREATE INDEX IF NOT EXISTS idx_raw_cvehistory_cve_id ON raw_cvehistory_documents(cve_id);
CREATE INDEX IF NOT EXISTS idx_nvd_cpe_vendor ON nvd_cpes(vendor);
CREATE INDEX IF NOT EXISTS idx_nvd_cpe_product ON nvd_cpes(product);
CREATE INDEX IF NOT EXISTS idx_nvd_cpe_name ON nvd_cpes(cpe_name);
CREATE INDEX IF NOT EXISTS idx_nvd_match_criteria ON nvd_match_strings(criteria);
CREATE INDEX IF NOT EXISTS idx_nvd_match_status ON nvd_match_strings(status);
CREATE INDEX IF NOT EXISTS idx_nvd_match_cpe_name ON nvd_match_string_matches(cpe_name);
CREATE INDEX IF NOT EXISTS idx_nvd_source_identifier ON nvd_source_identifiers(source_identifier);
CREATE INDEX IF NOT EXISTS idx_nvd_cve_change_cve_id ON nvd_cve_changes(cve_id);
CREATE INDEX IF NOT EXISTS idx_nvd_cve_change_created ON nvd_cve_changes(created);
CREATE INDEX IF NOT EXISTS idx_vendor_name ON vendors(name);
CREATE INDEX IF NOT EXISTS idx_product_name ON products(name);
CREATE INDEX IF NOT EXISTS idx_description_lang ON cve_descriptions(lang);
CREATE INDEX IF NOT EXISTS idx_metric_key ON cve_metrics(metric_key);
CREATE INDEX IF NOT EXISTS idx_reference_url ON cve_references(url);
CREATE INDEX IF NOT EXISTS idx_match_criteria ON cve_matches(criteria);
