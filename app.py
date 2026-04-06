"""
AuditPro — Departmental Store Audit System (Tamil Nadu, India)
==============================================================
Full REST API backend with SQLite for a comprehensive departmental
store audit platform covering Financial, IT, Inventory, Legal,
HR, Operations, Security, and Compliance audits.

Install:
    pip install flask flask-cors werkzeug

Run:
    python app.py

API: http://localhost:5000
DB:  auditpro_store.db
"""

from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, uuid
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__, static_folder='.')
CORS(app)
DATABASE = 'auditpro_store.db'


# ─── DATABASE ────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db: db.close()

def query_db(sql, args=(), one=False, commit=False):
    db = get_db()
    cur = db.execute(sql, args)
    if commit:
        db.commit()
        return cur.lastrowid
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

def row_to_dict(row):
    return dict(row) if row else None

def rows_to_list(rows):
    return [dict(r) for r in rows]


# ─── SCHEMA ──────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK(role IN ('user','company')),
    fname         TEXT NOT NULL,
    lname         TEXT NOT NULL,
    company       TEXT DEFAULT '',
    created_at    TEXT NOT NULL,
    last_login    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audits (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    auditor     TEXT NOT NULL,
    department  TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT 'General',
    date        TEXT NOT NULL,
    status      TEXT NOT NULL CHECK(status IN ('pass','fail','warning','review')),
    priority    TEXT NOT NULL CHECK(priority IN ('high','medium','low')),
    risk_score  INTEGER DEFAULT 50,
    notes       TEXT DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS compliance (
    id          TEXT PRIMARY KEY,
    requirement TEXT NOT NULL,
    framework   TEXT NOT NULL,
    owner       TEXT NOT NULL,
    due_date    TEXT NOT NULL,
    status      TEXT NOT NULL CHECK(status IN ('pass','fail','warning','review')),
    score       INTEGER DEFAULT 0,
    authority   TEXT DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS inventory_audits (
    id              TEXT PRIMARY KEY,
    item_name       TEXT NOT NULL,
    category        TEXT NOT NULL,
    system_qty      INTEGER NOT NULL,
    physical_qty    INTEGER NOT NULL,
    unit_price      REAL DEFAULT 0,
    location        TEXT DEFAULT '',
    expiry_date     TEXT DEFAULT '',
    status          TEXT NOT NULL CHECK(status IN ('match','shortage','excess','expired','damaged')),
    discrepancy     INTEGER DEFAULT 0,
    auditor         TEXT NOT NULL,
    audit_date      TEXT NOT NULL,
    notes           TEXT DEFAULT '',
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gst_compliance (
    id              TEXT PRIMARY KEY,
    period          TEXT NOT NULL,
    gst_number      TEXT NOT NULL,
    filing_type     TEXT NOT NULL,
    due_date        TEXT NOT NULL,
    filed_date      TEXT DEFAULT '',
    status          TEXT NOT NULL CHECK(status IN ('filed','pending','overdue','under_review')),
    tax_amount      REAL DEFAULT 0,
    itc_claimed     REAL DEFAULT 0,
    discrepancy     REAL DEFAULT 0,
    remarks         TEXT DEFAULT '',
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hr_compliance (
    id              TEXT PRIMARY KEY,
    employee_id     TEXT NOT NULL,
    employee_name   TEXT NOT NULL,
    designation     TEXT NOT NULL,
    department      TEXT NOT NULL,
    joining_date    TEXT NOT NULL,
    pf_status       TEXT DEFAULT 'active',
    esi_status      TEXT DEFAULT 'active',
    min_wage_status TEXT DEFAULT 'compliant',
    training_status TEXT DEFAULT 'complete',
    attendance_pct  REAL DEFAULT 100,
    remarks         TEXT DEFAULT '',
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS it_assets (
    id              TEXT PRIMARY KEY,
    asset_name      TEXT NOT NULL,
    asset_type      TEXT NOT NULL,
    serial_number   TEXT DEFAULT '',
    location        TEXT NOT NULL,
    purchase_date   TEXT DEFAULT '',
    warranty_expiry TEXT DEFAULT '',
    status          TEXT NOT NULL CHECK(status IN ('operational','faulty','maintenance','disposed','under_review')),
    last_audit_date TEXT DEFAULT '',
    software_license TEXT DEFAULT '',
    antivirus_status TEXT DEFAULT 'active',
    patch_status    TEXT DEFAULT 'updated',
    assigned_to     TEXT DEFAULT '',
    notes           TEXT DEFAULT '',
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS licenses (
    id              TEXT PRIMARY KEY,
    license_name    TEXT NOT NULL,
    license_type    TEXT NOT NULL,
    authority       TEXT NOT NULL,
    license_number  TEXT DEFAULT '',
    issue_date      TEXT NOT NULL,
    expiry_date     TEXT NOT NULL,
    status          TEXT NOT NULL CHECK(status IN ('valid','expired','renewal_due','suspended','applied')),
    renewal_reminder INTEGER DEFAULT 30,
    documents       TEXT DEFAULT '',
    notes           TEXT DEFAULT '',
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity (
    id         TEXT PRIMARY KEY,
    type       TEXT NOT NULL,
    message    TEXT NOT NULL,
    meta       TEXT DEFAULT '',
    color      TEXT DEFAULT 'blue',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id         TEXT PRIMARY KEY,
    title      TEXT NOT NULL,
    type       TEXT NOT NULL,
    date       TEXT NOT NULL,
    status     TEXT NOT NULL,
    size       TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
"""


# ─── SEED DATA ────────────────────────────────────────────────

def seed_database():
    db = get_db()
    existing = db.execute("SELECT COUNT(*) as cnt FROM users").fetchone()
    if existing["cnt"] > 0:
        return

    now = datetime.now().isoformat()

    users = [
        ("u001","user@demo.com",    generate_password_hash("demo1234"),"user",   "Arjun","Kumar","",                    "2024-01-15",now),
        ("u002","company@demo.com", generate_password_hash("demo1234"),"company","Priya","Venkatesh","Sri Murugan Stores","2024-01-01",now),
        ("u003","ravi@demo.com",    generate_password_hash("demo1234"),"user",   "Ravi","Shankar","",                    "2024-02-10",now),
        ("u004","meena@demo.com",   generate_password_hash("demo1234"),"user",   "Meena","Sundaram","",                  "2024-03-05",now),
    ]
    db.executemany("INSERT OR IGNORE INTO users VALUES (?,?,?,?,?,?,?,?,?)", users)

    audits = [
        ("AU-3001","GST Filing Verification",         "Priya Venkatesh","Finance","GST Compliance", "2025-04-03","pass",   "high",  78,"GSTR-1 and GSTR-3B filed on time. ITC reconciled.",now),
        ("AU-3002","Cash Register Reconciliation",    "Ravi Shankar",   "Finance","Financial",      "2025-04-02","warning","high",  65,"₹2,340 discrepancy found in cash register for Mar 28.",now),
        ("AU-3003","POS System Security Audit",       "Meena Sundaram", "IT","IT Infrastructure",   "2025-04-01","fail",   "high",  88,"POS terminal software outdated. PCI-DSS non-compliance.",now),
        ("AU-3004","FSSAI Compliance Check",          "Arjun Kumar",    "Legal","Regulatory",        "2025-03-31","pass",   "medium",30,"FSSAI license valid. Cold chain maintained properly.",now),
        ("AU-3005","Stock Physical Verification",     "Ravi Shankar",   "Inventory","Inventory",     "2025-03-28","warning","medium",55,"12 SKUs showed discrepancy >5%. Shrinkage detected.",now),
        ("AU-3006","Employee PF/ESI Audit",           "Meena Sundaram", "HR","HR Compliance",        "2025-03-26","pass",   "low",   20,"PF and ESI deductions compliant for all 48 employees.",now),
        ("AU-3007","CCTV & Physical Security",        "Arjun Kumar",    "Operations","Security",     "2025-03-24","warning","medium",50,"2 blind spots identified near dairy section.",now),
        ("AU-3008","Weights & Measures Verification", "Ravi Shankar",   "Legal","Regulatory",        "2025-03-20","pass",   "medium",25,"All weighing scales certified by Legal Metrology Dept.",now),
        ("AU-3009","IT Network Security",             "Meena Sundaram", "IT","IT Infrastructure",    "2025-03-18","fail",   "high",  82,"Guest WiFi unencrypted. Customer data risk identified.",now),
        ("AU-3010","Payroll Compliance",              "Priya Venkatesh","HR","HR Compliance",         "2025-03-15","pass",   "low",   15,"Salary disbursed per Tamil Nadu minimum wages act.",now),
        ("AU-3011","Fire Safety Audit",               "Arjun Kumar",    "Operations","Safety",       "2025-03-10","warning","high",  60,"2 fire extinguishers expired. Emergency exit partially blocked.",now),
        ("AU-3012","Vendor Invoice Audit",            "Ravi Shankar",   "Finance","Financial",       "2025-03-05","pass",   "medium",35,"All vendor invoices matched with GRN records.",now),
        ("AU-3013","Plastic Ban Compliance",          "Meena Sundaram", "Legal","Regulatory",        "2025-03-01","fail",   "high",  75,"Single-use plastic bags found in storeroom. TN ban violation.",now),
        ("AU-3014","Data Backup & Recovery",          "Arjun Kumar",    "IT","IT Infrastructure",    "2025-02-25","pass",   "medium",40,"Daily backups running. Recovery tested successfully.",now),
        ("AU-3015","Expired Product Audit",           "Ravi Shankar",   "Inventory","Inventory",     "2025-02-20","fail",   "high",  90,"23 expired products found on shelves. FSSAI violation risk.",now),
    ]
    db.executemany("INSERT OR IGNORE INTO audits VALUES (?,?,?,?,?,?,?,?,?,?,?)", audits)

    compliance = [
        ("c001","GST Registration & Filing",         "GST",         "Finance",    "2025-04-15","pass",   96,"GST Portal",now),
        ("c002","FSSAI License Renewal",             "FSSAI",       "Operations", "2025-06-30","warning",78,"FSSAI Authority",now),
        ("c003","Shop & Establishment Registration", "TN Labour",   "HR",         "2025-12-31","pass",   98,"TN Labour Dept",now),
        ("c004","Weights & Measures Certification",  "Legal Metrology","Operations","2025-09-01","pass",  92,"Legal Metrology",now),
        ("c005","Fire NOC Renewal",                  "Fire Safety", "Operations", "2025-07-15","warning",65,"TN Fire & Rescue",now),
        ("c006","PCI-DSS POS Compliance",            "PCI-DSS",     "IT",         "2025-05-01","fail",   55,"PCI Council",now),
        ("c007","Trade License Renewal",             "Municipal",   "Legal",      "2025-03-31","fail",   40,"Coimbatore Corporation",now),
        ("c008","ESI & PF Filings",                  "Labour Law",  "HR",         "2025-04-20","pass",   94,"EPFO / ESIC",now),
        ("c009","Plastic Ban Compliance",            "TN Govt",     "Operations", "2025-04-01","fail",   30,"TNPCB",now),
        ("c010","E-Invoice GST Compliance",          "GST",         "Finance",    "2025-04-30","pass",   88,"GST Portal",now),
    ]
    db.executemany("INSERT OR IGNORE INTO compliance VALUES (?,?,?,?,?,?,?,?,?)", compliance)

    inventory = [
        ("INV001","Basmati Rice 5kg",     "Food Grains",  500,487, 285.00,"Aisle 1","2026-12-31","shortage",-13,"Ravi Shankar","2025-04-01","Possible pilferage",now),
        ("INV002","Toor Dal 1kg",         "Pulses",       300,302, 95.00, "Aisle 2","2026-06-30","excess",  2, "Ravi Shankar","2025-04-01","Minor excess",now),
        ("INV003","Amul Butter 500g",     "Dairy",        150,148, 270.00,"Cold Storage","2025-05-15","shortage",-2,"Meena Sundaram","2025-04-01","",now),
        ("INV004","Parachute Oil 1L",     "Edible Oils",  200,200, 175.00,"Aisle 4","2027-03-31","match",   0, "Meena Sundaram","2025-04-01","",now),
        ("INV005","Expired Bread (Aro)",  "Bakery",       0,  23,  45.00, "Shelf B3","2025-03-28","expired",23,"Arjun Kumar",  "2025-04-02","URGENT: Remove immediately",now),
        ("INV006","Colgate Toothpaste",   "Personal Care",250,245, 110.00,"Aisle 6","2027-01-01","shortage",-5,"Arjun Kumar",  "2025-04-02","",now),
        ("INV007","Damaged Biscuit Packs","Snacks",       0,  8,   30.00, "Storeroom","2025-12-31","damaged",8,"Ravi Shankar","2025-04-01","Damaged in transit",now),
        ("INV008","Pepsi 2L",             "Beverages",    400,399, 95.00, "Aisle 7","2025-08-01","shortage",-1,"Meena Sundaram","2025-04-01","",now),
        ("INV009","Surf Excel 1kg",       "Detergents",   180,185, 235.00,"Aisle 8","2027-06-30","excess",  5, "Arjun Kumar",  "2025-04-02","Received extra",now),
        ("INV010","Cadbury Dairy Milk",   "Chocolates",   500,478, 60.00, "Counter","2025-10-01","shortage",-22,"Ravi Shankar","2025-04-01","High shrinkage - review CCTV",now),
    ]
    db.executemany("INSERT OR IGNORE INTO inventory_audits VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", inventory)

    gst = [
        ("GST001","2025-03","29ABCDE1234F1Z5","GSTR-1", "2025-04-11","2025-04-10","filed",      125430.50,18200.00,0,    "Filed on time",now),
        ("GST002","2025-03","29ABCDE1234F1Z5","GSTR-3B","2025-04-20","2025-04-19","filed",      98750.00, 18200.00,0,    "ITC matched",now),
        ("GST003","2025-02","29ABCDE1234F1Z5","GSTR-1", "2025-03-11","2025-03-11","filed",      118920.00,16450.00,0,    "",now),
        ("GST004","2025-02","29ABCDE1234F1Z5","GSTR-3B","2025-03-20","2025-03-21","overdue",    99100.00, 16450.00,850.0,"Filed 1 day late - penalty applicable",now),
        ("GST005","2025-01","29ABCDE1234F1Z5","GSTR-1", "2025-02-11","2025-02-10","filed",      105600.00,14200.00,0,    "",now),
        ("GST006","2025-04","29ABCDE1234F1Z5","GSTR-1", "2025-05-11","","pending",              0,        0,       0,    "Due next month",now),
        ("GST007","2025-04","29ABCDE1234F1Z5","GSTR-3B","2025-04-20","","under_review",         135000.00,20100.00,1200.0,"ITC mismatch - under reconciliation",now),
    ]
    db.executemany("INSERT OR IGNORE INTO gst_compliance VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", gst)

    hr = [
        ("HR001","EMP001","Murugan S.",    "Store Manager",  "Management", "2018-06-01","active",  "active",  "compliant",    "complete", 98.5,"",now),
        ("HR002","EMP002","Kavitha R.",    "Cashier",        "Billing",    "2020-03-15","active",  "active",  "compliant",    "complete", 96.2,"",now),
        ("HR003","EMP003","Suresh K.",     "Floor Staff",    "Operations", "2021-08-10","active",  "active",  "compliant",    "pending",  92.0,"Training pending",now),
        ("HR004","EMP004","Lakshmi N.",    "Inventory Mgr",  "Inventory",  "2019-11-20","active",  "active",  "compliant",    "complete", 97.8,"",now),
        ("HR005","EMP005","Ramesh T.",     "Security Guard", "Security",   "2022-01-05","inactive","inactive","non_compliant","complete", 88.5,"Contract employee - PF/ESI gap",now),
        ("HR006","EMP006","Vijaya M.",     "Billing Asst",   "Billing",    "2023-05-12","active",  "active",  "compliant",    "complete", 99.0,"",now),
        ("HR007","EMP007","Karthik P.",    "Delivery Staff", "Logistics",  "2022-09-30","active",  "inactive","compliant",    "pending",  85.3,"ESI not enrolled - verify status",now),
        ("HR008","EMP008","Anitha D.",     "Customer Svc",   "Operations", "2021-04-22","active",  "active",  "compliant",    "complete", 94.7,"",now),
    ]
    db.executemany("INSERT OR IGNORE INTO hr_compliance VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", hr)

    it_assets = [
        ("IT001","POS Terminal 1",    "POS System",     "POS-BIL-001","Billing Counter 1","2022-01-15","2025-01-15","faulty",   "2025-04-01","RetailEasy v3.1","active","outdated","Cashier 1","POS software not updated - PCI risk",now),
        ("IT002","POS Terminal 2",    "POS System",     "POS-BIL-002","Billing Counter 2","2022-01-15","2025-01-15","operational","2025-04-01","RetailEasy v3.2","active","updated","Cashier 2","",now),
        ("IT003","Inventory Server",  "Server",         "SRV-INV-001","Server Room",      "2021-06-10","2024-06-10","maintenance","2025-03-15","Tally ERP 9",   "active","outdated","IT Admin","Warranty expired. Schedule replacement.",now),
        ("IT004","Manager PC",        "Desktop",        "PC-MGR-001", "Manager Cabin",    "2023-03-01","2026-03-01","operational","2025-04-01","Tally Prime",   "active","updated","Store Mgr","",now),
        ("IT005","CCTV DVR Unit",     "Security",       "DVR-SEC-001","Security Room",    "2020-11-01","2023-11-01","operational","2025-04-01","N/A",           "active","updated","Security","Warranty expired. Retention only 15 days (need 30).",now),
        ("IT006","WiFi Router",       "Network",        "RTR-NET-001","Billing Area",     "2021-05-20","2024-05-20","under_review","2025-04-01","N/A",          "active","outdated","IT Admin","Guest WiFi unencrypted - security risk",now),
        ("IT007","Barcode Scanner 1", "Scanner",        "SCN-INV-001","Inventory Desk",   "2023-08-10","2026-08-10","operational","2025-04-01","N/A",           "N/A","N/A","Inventory Staff","",now),
        ("IT008","UPI Payment Terminal","Payment",      "UPI-POS-001","Billing Counter 1","2024-01-01","2027-01-01","operational","2025-04-01","N/A",           "active","updated","Cashier 1","",now),
        ("IT009","Billing Printer",   "Printer",        "PRT-BIL-001","Billing Counter 1","2022-06-15","2025-06-15","operational","2025-04-01","N/A",           "N/A","N/A","Cashier 1","",now),
        ("IT010","Backup HDD",        "Storage",        "HDD-BKP-001","Server Room",      "2023-01-10","2026-01-10","operational","2025-04-01","N/A",           "N/A","N/A","IT Admin","Daily backup running",now),
    ]
    db.executemany("INSERT OR IGNORE INTO it_assets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", it_assets)

    licenses = [
        ("LIC001","GST Registration",           "Tax",        "GST Portal",             "29ABCDE1234F1Z5","2018-07-01","2099-12-31","valid",   30,"GST cert available","",now),
        ("LIC002","FSSAI License",              "Food Safety","FSSAI Authority",         "TN-12345678",   "2024-07-01","2025-06-30","renewal_due",60,"FSSAI doc present","Renewal in 87 days",now),
        ("LIC003","Shop & Establishment",       "Labour",     "TN Labour Dept",          "TN/CBE/2018/001","2018-01-15","2025-12-31","valid",   90,"S&E certificate",  "",now),
        ("LIC004","Trade License",              "Municipal",  "Coimbatore Corporation",  "CBE/TL/2024/888","2024-04-01","2025-03-31","expired", 30,"Trade license copy","EXPIRED - Renew immediately",now),
        ("LIC005","Weights & Measures Cert.",   "Regulatory", "Legal Metrology Dept",    "LM/TN/2024/456","2024-09-01","2025-08-31","valid",   60,"WM certificate",   "",now),
        ("LIC006","Fire NOC",                   "Safety",     "TN Fire & Rescue Dept",   "FIRE/CBE/2023/222","2023-07-15","2024-07-14","expired",30,"NOC copy",        "EXPIRED - Renew urgently",now),
        ("LIC007","TNPCB Consent",              "Environment","Tamil Nadu PCB",           "TNPCB/2023/444","2023-06-01","2025-05-31","renewal_due",60,"TNPCB consent",  "Renewal due soon",now),
        ("LIC008","PF Registration",            "Labour",     "EPFO",                    "TN/CBE/12345",  "2018-06-15","2099-12-31","valid",   30,"PF registration",  "",now),
        ("LIC009","ESI Registration",           "Labour",     "ESIC",                    "ESI/TN/2018/99","2018-06-15","2099-12-31","valid",   30,"ESI certificate",  "",now),
        ("LIC010","Drug License",               "Regulatory","TN Drug Control",           "TN/DL/2022/555","2022-03-01","2025-02-28","expired", 30,"Drug license",     "EXPIRED if store sells OTC medicines",now),
    ]
    db.executemany("INSERT OR IGNORE INTO licenses VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", licenses)

    activities = [
        ("a001","audit_complete","GST Audit #AU-3001 — All filings verified",   "Finance Dept",       "green","2025-04-05T09:22:00"),
        ("a002","critical_flag", "CRITICAL: Expired products on shelves #AU-3015","Inventory — URGENT","red",  "2025-04-05T09:08:00"),
        ("a003","compliance_upd","Trade License EXPIRED — Immediate renewal needed","Coimbatore Corp",  "red",  "2025-04-05T08:30:00"),
        ("a004","warning",       "Cash discrepancy ₹2,340 found — #AU-3002",    "Finance Dept",       "gold", "2025-04-05T08:00:00"),
        ("a005","audit_fail",    "POS Terminal non-compliant — PCI-DSS Risk",    "IT Department",      "red",  "2025-04-04T14:30:00"),
        ("a006","compliance_upd","Fire NOC expired — Renew with TN Fire Dept",   "Operations",         "red",  "2025-04-04T11:00:00"),
        ("a007","audit_complete","Weights & Measures #AU-3008 — All scales certified","Legal Metrology","blue","2025-04-03T15:45:00"),
        ("a008","critical_flag", "Plastic ban violation found in storeroom",      "Operations — TNPCB", "red", "2025-04-03T10:00:00"),
    ]
    db.executemany("INSERT OR IGNORE INTO activity VALUES (?,?,?,?,?,?)", activities)

    reports_data = [
        ("r001","Q1 2025 Store Audit Summary",    "quarterly","2025-03-31","finalized","5.8 MB",now),
        ("r002","GST Compliance Report 2024-25",  "gst",      "2025-03-31","finalized","2.1 MB",now),
        ("r003","Inventory Shrinkage Analysis",   "inventory","2025-02-28","review",   "1.4 MB",now),
        ("r004","IT Infrastructure Audit",        "it",       "2025-01-20","issues",   "3.2 MB",now),
        ("r005","HR & Labour Compliance",         "hr",       "2025-03-10","finalized","2.9 MB",now),
        ("r006","License Status Report",          "legal",    "2025-04-01","issues",   "0.9 MB",now),
        ("r007","Fire & Safety Audit Report",     "safety",   "2025-03-05","issues",   "1.6 MB",now),
    ]
    db.executemany("INSERT OR IGNORE INTO reports VALUES (?,?,?,?,?,?,?)", reports_data)

    db.commit()
    print("  ✅ Database seeded with Departmental Store audit data.")


def init_db():
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA)
        db.commit()
        seed_database()
    print(f"  ✅ SQLite database ready: {os.path.abspath(DATABASE)}")


# ─── AUTH HELPERS ─────────────────────────────────────────────

def generate_token(user_id):
    token   = uuid.uuid4().hex + uuid.uuid4().hex
    expires = (datetime.now() + timedelta(days=7)).isoformat()
    query_db("INSERT INTO sessions (token,user_id,expires_at,created_at) VALUES (?,?,?,?)",
             (token, user_id, expires, datetime.now().isoformat()), commit=True)
    return token

def get_user_from_token(token):
    if not token: return None
    row = query_db("SELECT * FROM sessions WHERE token=?", (token,), one=True)
    if not row: return None
    if datetime.fromisoformat(row["expires_at"]) < datetime.now():
        query_db("DELETE FROM sessions WHERE token=?", (token,), commit=True)
        return None
    return row_to_dict(query_db("SELECT * FROM users WHERE id=?", (row["user_id"],), one=True))

def safe_user(user):
    if not user: return {}
    return {k: v for k, v in user.items() if k != "password_hash"}

def log_activity(atype, message, meta="", color="blue"):
    query_db("INSERT INTO activity (id,type,message,meta,color,created_at) VALUES (?,?,?,?,?,?)",
             (uuid.uuid4().hex[:8], atype, message, meta, color, datetime.now().isoformat()),
             commit=True)


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization","").replace("Bearer ","").strip()
        user  = get_user_from_token(token)
        if not user: return jsonify({"error": "Unauthorized."}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

def require_company(f):
    @wraps(f)
    @require_auth
    def decorated(*args, **kwargs):
        if request.current_user.get("role") != "company":
            return jsonify({"error": "Company admin access required."}), 403
        return f(*args, **kwargs)
    return decorated


# ============================================================
# AUTH ROUTES
# ============================================================

@app.route("/api/auth/login", methods=["POST"])
def login():
    data  = request.get_json() or {}
    email = data.get("email","").strip().lower()
    pw    = data.get("password","")
    role  = data.get("role","user")
    if not email or not pw:
        return jsonify({"error": "Email and password required"}), 400
    user = row_to_dict(query_db("SELECT * FROM users WHERE email=? AND role=?", (email, role), one=True))
    if not user or not check_password_hash(user["password_hash"], pw):
        return jsonify({"error": "Invalid credentials or role"}), 401
    query_db("UPDATE users SET last_login=? WHERE id=?", (datetime.now().isoformat(), user["id"]), commit=True)
    token = generate_token(user["id"])
    log_activity("login", f"{user['fname']} {user['lname']} signed in", f"Role: {role}", "blue")
    return jsonify({"token": token, "user": safe_user(user)}), 200

@app.route("/api/auth/register", methods=["POST"])
def register():
    data    = request.get_json() or {}
    email   = data.get("email","").strip().lower()
    pw      = data.get("password","")
    fname   = data.get("fname","").strip()
    lname   = data.get("lname","").strip()
    role    = data.get("role","user")
    company = data.get("company","").strip()
    if not all([email, pw, fname, lname]):
        return jsonify({"error": "All fields required"}), 400
    if len(pw) < 8:
        return jsonify({"error": "Password min 8 chars"}), 400
    if query_db("SELECT id FROM users WHERE email=?", (email,), one=True):
        return jsonify({"error": "Email already registered"}), 409
    uid = "u" + uuid.uuid4().hex[:8]
    now = datetime.now().isoformat()
    query_db("INSERT INTO users (id,email,password_hash,role,fname,lname,company,created_at,last_login) VALUES (?,?,?,?,?,?,?,?,?)",
             (uid, email, generate_password_hash(pw), role, fname, lname, company, now, now), commit=True)
    user  = row_to_dict(query_db("SELECT * FROM users WHERE id=?", (uid,), one=True))
    token = generate_token(uid)
    log_activity("user_added", f"{fname} {lname} registered", f"Role: {role}", "green")
    return jsonify({"token": token, "user": safe_user(user)}), 201

@app.route("/api/auth/logout", methods=["POST"])
@require_auth
def logout():
    token = request.headers.get("Authorization","").replace("Bearer ","").strip()
    query_db("DELETE FROM sessions WHERE token=?", (token,), commit=True)
    return jsonify({"message": "Logged out"}), 200

@app.route("/api/auth/me", methods=["GET"])
@require_auth
def get_me():
    return jsonify(safe_user(request.current_user)), 200


# ============================================================
# DASHBOARD METRICS
# ============================================================

@app.route("/api/dashboard/metrics", methods=["GET"])
@require_auth
def get_metrics():
    total   = query_db("SELECT COUNT(*) as c FROM audits", one=True)["c"]
    passed  = query_db("SELECT COUNT(*) as c FROM audits WHERE status='pass'", one=True)["c"]
    failed  = query_db("SELECT COUNT(*) as c FROM audits WHERE status='fail'", one=True)["c"]
    warning = query_db("SELECT COUNT(*) as c FROM audits WHERE status='warning'", one=True)["c"]
    comp    = query_db("SELECT AVG(score) as a FROM compliance", one=True)["a"] or 0

    inv_total     = query_db("SELECT COUNT(*) as c FROM inventory_audits", one=True)["c"]
    inv_issues    = query_db("SELECT COUNT(*) as c FROM inventory_audits WHERE status!='match'", one=True)["c"]
    expired_items = query_db("SELECT COUNT(*) as c FROM inventory_audits WHERE status='expired'", one=True)["c"]

    lic_expired = query_db("SELECT COUNT(*) as c FROM licenses WHERE status='expired'", one=True)["c"]
    lic_due     = query_db("SELECT COUNT(*) as c FROM licenses WHERE status='renewal_due'", one=True)["c"]

    gst_overdue = query_db("SELECT COUNT(*) as c FROM gst_compliance WHERE status='overdue'", one=True)["c"]
    gst_pending = query_db("SELECT COUNT(*) as c FROM gst_compliance WHERE status='pending'", one=True)["c"]

    it_faulty = query_db("SELECT COUNT(*) as c FROM it_assets WHERE status='faulty' OR status='under_review'", one=True)["c"]

    hr_issues = query_db("SELECT COUNT(*) as c FROM hr_compliance WHERE pf_status!='active' OR esi_status!='active' OR min_wage_status!='compliant'", one=True)["c"]

    return jsonify({
        "total_audits": total,
        "passed": passed,
        "failed": failed,
        "warnings": warning,
        "compliance_score": round(comp, 1),
        "critical_issues": failed + warning,
        "inventory_issues": inv_issues,
        "expired_items": expired_items,
        "licenses_expired": lic_expired,
        "licenses_due": lic_due,
        "gst_overdue": gst_overdue,
        "gst_pending": gst_pending,
        "it_assets_issues": it_faulty,
        "hr_issues": hr_issues,
        "pass_rate": round(passed / total * 100, 1) if total else 0,
        "inv_total": inv_total,
    }), 200

@app.route("/api/dashboard/activity", methods=["GET"])
@require_auth
def get_activity():
    rows = query_db("SELECT * FROM activity ORDER BY created_at DESC LIMIT 10")
    return jsonify(rows_to_list(rows)), 200


# ============================================================
# AUDITS
# ============================================================

@app.route("/api/audits", methods=["GET"])
@require_auth
def get_audits():
    page     = max(1, int(request.args.get("page", 1)))
    per_page = min(50, int(request.args.get("per_page", 15)))
    status   = request.args.get("status","")
    dept     = request.args.get("department","")
    priority = request.args.get("priority","")
    category = request.args.get("category","")
    search   = request.args.get("search","")

    conditions, params = [], []
    if status:   conditions.append("status=?");                   params.append(status)
    if dept:     conditions.append("LOWER(department)=LOWER(?)"); params.append(dept)
    if priority: conditions.append("priority=?");                 params.append(priority)
    if category: conditions.append("LOWER(category)=LOWER(?)");   params.append(category)
    if search:
        conditions.append("(LOWER(title) LIKE ? OR LOWER(department) LIKE ? OR LOWER(auditor) LIKE ? OR LOWER(category) LIKE ?)")
        like = f"%{search.lower()}%"
        params.extend([like, like, like, like])

    where  = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    total  = query_db(f"SELECT COUNT(*) as c FROM audits {where}", params, one=True)["c"]
    offset = (page-1) * per_page
    rows   = query_db(f"SELECT * FROM audits {where} ORDER BY date DESC LIMIT ? OFFSET ?", params + [per_page, offset])
    return jsonify({"audits": rows_to_list(rows), "total": total, "page": page, "per_page": per_page,
                    "pages": max(1,(total+per_page-1)//per_page)}), 200

@app.route("/api/audits/<audit_id>", methods=["GET"])
@require_auth
def get_audit(audit_id):
    row = query_db("SELECT * FROM audits WHERE id=?", (audit_id,), one=True)
    if not row: return jsonify({"error": "Not found"}), 404
    return jsonify(row_to_dict(row)), 200

@app.route("/api/audits", methods=["POST"])
@require_company
def create_audit():
    data = request.get_json() or {}
    for req in ["title","department","priority","category"]:
        if req not in data: return jsonify({"error": f"'{req}' required"}), 400
    u   = request.current_user
    last = query_db("SELECT id FROM audits ORDER BY created_at DESC LIMIT 1", one=True)
    try:    num = int(last["id"].split("-")[1]) if last else 3015
    except: num = 3015
    new_id = f"AU-{num+1}"
    now = datetime.now().isoformat()
    query_db("INSERT INTO audits (id,title,auditor,department,category,date,status,priority,risk_score,notes,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
             (new_id, data["title"], f"{u['fname']} {u['lname']}", data["department"], data["category"],
              datetime.now().strftime("%Y-%m-%d"), data.get("status","review"), data["priority"],
              int(data.get("risk_score",50)), data.get("notes",""), now), commit=True)
    log_activity("audit_created", f"New audit {new_id}: {data['title']}", data["department"], "blue")
    return jsonify(row_to_dict(query_db("SELECT * FROM audits WHERE id=?", (new_id,), one=True))), 201

@app.route("/api/audits/<audit_id>", methods=["PUT"])
@require_company
def update_audit(audit_id):
    if not query_db("SELECT id FROM audits WHERE id=?", (audit_id,), one=True):
        return jsonify({"error": "Not found"}), 404
    data = request.get_json() or {}
    fields = ["title","status","priority","risk_score","notes","department","auditor","category"]
    upd, params = [], []
    for f in fields:
        if f in data: upd.append(f"{f}=?"); params.append(data[f])
    if upd:
        params.append(audit_id)
        query_db(f"UPDATE audits SET {', '.join(upd)} WHERE id=?", params, commit=True)
        log_activity("audit_updated", f"Audit {audit_id} updated", "", "gold")
    return jsonify(row_to_dict(query_db("SELECT * FROM audits WHERE id=?", (audit_id,), one=True))), 200

@app.route("/api/audits/<audit_id>", methods=["DELETE"])
@require_company
def delete_audit(audit_id):
    if not query_db("SELECT id FROM audits WHERE id=?", (audit_id,), one=True):
        return jsonify({"error": "Not found"}), 404
    query_db("DELETE FROM audits WHERE id=?", (audit_id,), commit=True)
    log_activity("audit_deleted", f"Audit {audit_id} deleted", "", "red")
    return jsonify({"message": "Deleted"}), 200


# ============================================================
# INVENTORY AUDIT
# ============================================================

@app.route("/api/inventory", methods=["GET"])
@require_auth
def get_inventory():
    status   = request.args.get("status","")
    category = request.args.get("category","")
    search   = request.args.get("search","")
    conditions, params = [], []
    if status:   conditions.append("status=?"); params.append(status)
    if category: conditions.append("LOWER(category)=LOWER(?)"); params.append(category)
    if search:
        conditions.append("(LOWER(item_name) LIKE ? OR LOWER(category) LIKE ?)")
        like = f"%{search.lower()}%"; params.extend([like, like])
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    rows  = query_db(f"SELECT * FROM inventory_audits {where} ORDER BY audit_date DESC", params)
    summary = {
        "total": query_db("SELECT COUNT(*) as c FROM inventory_audits", one=True)["c"],
        "match": query_db("SELECT COUNT(*) as c FROM inventory_audits WHERE status='match'", one=True)["c"],
        "shortage": query_db("SELECT COUNT(*) as c FROM inventory_audits WHERE status='shortage'", one=True)["c"],
        "expired": query_db("SELECT COUNT(*) as c FROM inventory_audits WHERE status='expired'", one=True)["c"],
        "damaged": query_db("SELECT COUNT(*) as c FROM inventory_audits WHERE status='damaged'", one=True)["c"],
        "excess": query_db("SELECT COUNT(*) as c FROM inventory_audits WHERE status='excess'", one=True)["c"],
    }
    return jsonify({"items": rows_to_list(rows), "summary": summary}), 200

@app.route("/api/inventory", methods=["POST"])
@require_auth
def create_inventory():
    data = request.get_json() or {}
    for req in ["item_name","category","system_qty","physical_qty"]:
        if req not in data: return jsonify({"error": f"'{req}' required"}), 400
    sys_qty  = int(data["system_qty"])
    phy_qty  = int(data["physical_qty"])
    diff     = phy_qty - sys_qty
    # Only use status override if it's a non-empty string
    override = data.get("status","").strip()
    if override: status = override
    elif diff < 0: status = "shortage"
    elif diff > 0: status = "excess"
    else: status = "match"
    # Use auditor from body or fall back to logged-in user
    auditor = data.get("auditor","").strip() or (request.current_user["fname"] + " " + request.current_user["lname"])
    new_id = "INV" + uuid.uuid4().hex[:6].upper()
    now = datetime.now().isoformat()
    query_db("INSERT INTO inventory_audits (id,item_name,category,system_qty,physical_qty,unit_price,location,expiry_date,status,discrepancy,auditor,audit_date,notes,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
             (new_id, data["item_name"], data["category"], sys_qty, phy_qty,
              float(data.get("unit_price",0)), data.get("location",""),
              data.get("expiry_date",""), status, diff, auditor,
              datetime.now().strftime("%Y-%m-%d"), data.get("notes",""), now), commit=True)
    log_activity("inventory", f"Inventory audit: {data['item_name']} — {status}", data["category"],
                 "red" if status in ["expired","shortage"] else "blue")
    return jsonify(row_to_dict(query_db("SELECT * FROM inventory_audits WHERE id=?", (new_id,), one=True))), 201

@app.route("/api/inventory/<item_id>", methods=["PUT"])
@require_company
def update_inventory(item_id):
    if not query_db("SELECT id FROM inventory_audits WHERE id=?", (item_id,), one=True):
        return jsonify({"error": "Not found"}), 404
    data = request.get_json() or {}
    fields = ["item_name","category","system_qty","physical_qty","unit_price","location","expiry_date","status","notes","auditor"]
    upd, params = [], []
    for f in fields:
        if f in data: upd.append(f"{f}=?"); params.append(data[f])
    if "system_qty" in data and "physical_qty" in data:
        diff = int(data["physical_qty"]) - int(data["system_qty"])
        upd.append("discrepancy=?"); params.append(diff)
    if upd:
        params.append(item_id)
        query_db(f"UPDATE inventory_audits SET {', '.join(upd)} WHERE id=?", params, commit=True)
    return jsonify(row_to_dict(query_db("SELECT * FROM inventory_audits WHERE id=?", (item_id,), one=True))), 200

@app.route("/api/inventory/<item_id>", methods=["DELETE"])
@require_company
def delete_inventory(item_id):
    if not query_db("SELECT id FROM inventory_audits WHERE id=?", (item_id,), one=True):
        return jsonify({"error": "Not found"}), 404
    query_db("DELETE FROM inventory_audits WHERE id=?", (item_id,), commit=True)
    return jsonify({"message": "Deleted"}), 200


# ============================================================
# GST COMPLIANCE
# ============================================================

@app.route("/api/gst", methods=["GET"])
@require_auth
def get_gst():
    rows = query_db("SELECT * FROM gst_compliance ORDER BY period DESC")
    summary = {
        "filed":        query_db("SELECT COUNT(*) as c FROM gst_compliance WHERE status='filed'", one=True)["c"],
        "pending":      query_db("SELECT COUNT(*) as c FROM gst_compliance WHERE status='pending'", one=True)["c"],
        "overdue":      query_db("SELECT COUNT(*) as c FROM gst_compliance WHERE status='overdue'", one=True)["c"],
        "under_review": query_db("SELECT COUNT(*) as c FROM gst_compliance WHERE status='under_review'", one=True)["c"],
        "total_tax":    query_db("SELECT SUM(tax_amount) as s FROM gst_compliance WHERE status='filed'", one=True)["s"] or 0,
        "total_itc":    query_db("SELECT SUM(itc_claimed) as s FROM gst_compliance WHERE status='filed'", one=True)["s"] or 0,
    }
    return jsonify({"filings": rows_to_list(rows), "summary": summary}), 200

@app.route("/api/gst", methods=["POST"])
@require_company
def create_gst():
    data = request.get_json() or {}
    for req in ["period","gst_number","filing_type","due_date"]:
        if req not in data: return jsonify({"error": f"'{req}' required"}), 400
    new_id = "GST" + uuid.uuid4().hex[:6].upper()
    now = datetime.now().isoformat()
    query_db("INSERT INTO gst_compliance (id,period,gst_number,filing_type,due_date,filed_date,status,tax_amount,itc_claimed,discrepancy,remarks,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
             (new_id, data["period"], data["gst_number"], data["filing_type"], data["due_date"],
              data.get("filed_date",""), data.get("status","pending"), float(data.get("tax_amount",0)),
              float(data.get("itc_claimed",0)), float(data.get("discrepancy",0)), data.get("remarks",""), now), commit=True)
    return jsonify(row_to_dict(query_db("SELECT * FROM gst_compliance WHERE id=?", (new_id,), one=True))), 201

@app.route("/api/gst/<gst_id>", methods=["PUT"])
@require_company
def update_gst(gst_id):
    if not query_db("SELECT id FROM gst_compliance WHERE id=?", (gst_id,), one=True):
        return jsonify({"error": "Not found"}), 404
    data = request.get_json() or {}
    fields = ["period","gst_number","filing_type","due_date","filed_date","status","tax_amount","itc_claimed","discrepancy","remarks"]
    upd, params = [], []
    for f in fields:
        if f in data: upd.append(f"{f}=?"); params.append(data[f])
    if upd:
        params.append(gst_id)
        query_db(f"UPDATE gst_compliance SET {', '.join(upd)} WHERE id=?", params, commit=True)
    return jsonify(row_to_dict(query_db("SELECT * FROM gst_compliance WHERE id=?", (gst_id,), one=True))), 200

@app.route("/api/gst/<gst_id>", methods=["DELETE"])
@require_company
def delete_gst(gst_id):
    if not query_db("SELECT id FROM gst_compliance WHERE id=?", (gst_id,), one=True):
        return jsonify({"error": "Not found"}), 404
    query_db("DELETE FROM gst_compliance WHERE id=?", (gst_id,), commit=True)
    return jsonify({"message": "Deleted"}), 200


# ============================================================
# HR COMPLIANCE
# ============================================================

@app.route("/api/hr", methods=["GET"])
@require_auth
def get_hr():
    rows = query_db("SELECT * FROM hr_compliance ORDER BY department ASC")
    summary = {
        "total":         query_db("SELECT COUNT(*) as c FROM hr_compliance", one=True)["c"],
        "pf_issues":     query_db("SELECT COUNT(*) as c FROM hr_compliance WHERE pf_status!='active'", one=True)["c"],
        "esi_issues":    query_db("SELECT COUNT(*) as c FROM hr_compliance WHERE esi_status!='active'", one=True)["c"],
        "wage_issues":   query_db("SELECT COUNT(*) as c FROM hr_compliance WHERE min_wage_status!='compliant'", one=True)["c"],
        "training_due":  query_db("SELECT COUNT(*) as c FROM hr_compliance WHERE training_status='pending'", one=True)["c"],
        "avg_attendance":query_db("SELECT AVG(attendance_pct) as a FROM hr_compliance", one=True)["a"] or 0,
    }
    return jsonify({"employees": rows_to_list(rows), "summary": summary}), 200

@app.route("/api/hr", methods=["POST"])
@require_company
def create_hr():
    data = request.get_json() or {}
    for req in ["employee_id","employee_name","designation","department","joining_date"]:
        if req not in data: return jsonify({"error": f"'{req}' required"}), 400
    new_id = "EMP" + uuid.uuid4().hex[:6].upper()
    now = datetime.now().isoformat()
    query_db("INSERT INTO hr_compliance (id,employee_id,employee_name,designation,department,joining_date,pf_status,esi_status,min_wage_status,training_status,attendance_pct,remarks,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
             (new_id, data["employee_id"], data["employee_name"], data["designation"],
              data["department"], data["joining_date"], data.get("pf_status","active"),
              data.get("esi_status","active"), data.get("min_wage_status","compliant"),
              data.get("training_status","complete"), float(data.get("attendance_pct",100)),
              data.get("remarks",""), now), commit=True)
    return jsonify(row_to_dict(query_db("SELECT * FROM hr_compliance WHERE id=?", (new_id,), one=True))), 201

@app.route("/api/hr/<hr_id>", methods=["PUT"])
@require_company
def update_hr(hr_id):
    if not query_db("SELECT id FROM hr_compliance WHERE id=?", (hr_id,), one=True):
        return jsonify({"error": "Not found"}), 404
    data = request.get_json() or {}
    fields = ["employee_name","designation","department","pf_status","esi_status","min_wage_status","training_status","attendance_pct","remarks"]
    upd, params = [], []
    for f in fields:
        if f in data: upd.append(f"{f}=?"); params.append(data[f])
    if upd:
        params.append(hr_id)
        query_db(f"UPDATE hr_compliance SET {', '.join(upd)} WHERE id=?", params, commit=True)
    return jsonify(row_to_dict(query_db("SELECT * FROM hr_compliance WHERE id=?", (hr_id,), one=True))), 200


# ============================================================
# IT ASSETS
# ============================================================

@app.route("/api/it-assets", methods=["GET"])
@require_auth
def get_it_assets():
    rows = query_db("SELECT * FROM it_assets ORDER BY asset_type ASC")
    summary = {
        "total":        query_db("SELECT COUNT(*) as c FROM it_assets", one=True)["c"],
        "operational":  query_db("SELECT COUNT(*) as c FROM it_assets WHERE status='operational'", one=True)["c"],
        "faulty":       query_db("SELECT COUNT(*) as c FROM it_assets WHERE status='faulty'", one=True)["c"],
        "maintenance":  query_db("SELECT COUNT(*) as c FROM it_assets WHERE status='maintenance'", one=True)["c"],
        "under_review": query_db("SELECT COUNT(*) as c FROM it_assets WHERE status='under_review'", one=True)["c"],
        "outdated_patch": query_db("SELECT COUNT(*) as c FROM it_assets WHERE patch_status='outdated'", one=True)["c"],
        "antivirus_issues": query_db("SELECT COUNT(*) as c FROM it_assets WHERE antivirus_status='inactive' OR antivirus_status='expired'", one=True)["c"],
    }
    return jsonify({"assets": rows_to_list(rows), "summary": summary}), 200

@app.route("/api/it-assets", methods=["POST"])
@require_company
def create_it_asset():
    data = request.get_json() or {}
    for req in ["asset_name","asset_type","location"]:
        if req not in data: return jsonify({"error": f"'{req}' required"}), 400
    new_id = "IT" + uuid.uuid4().hex[:6].upper()
    now = datetime.now().isoformat()
    query_db("INSERT INTO it_assets (id,asset_name,asset_type,serial_number,location,purchase_date,warranty_expiry,status,last_audit_date,software_license,antivirus_status,patch_status,assigned_to,notes,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
             (new_id, data["asset_name"], data["asset_type"], data.get("serial_number",""),
              data["location"], data.get("purchase_date",""), data.get("warranty_expiry",""),
              data.get("status","operational"), datetime.now().strftime("%Y-%m-%d"),
              data.get("software_license",""), data.get("antivirus_status","active"),
              data.get("patch_status","updated"), data.get("assigned_to",""), data.get("notes",""), now), commit=True)
    return jsonify(row_to_dict(query_db("SELECT * FROM it_assets WHERE id=?", (new_id,), one=True))), 201

@app.route("/api/it-assets/<asset_id>", methods=["PUT"])
@require_company
def update_it_asset(asset_id):
    if not query_db("SELECT id FROM it_assets WHERE id=?", (asset_id,), one=True):
        return jsonify({"error": "Not found"}), 404
    data = request.get_json() or {}
    fields = ["asset_name","asset_type","serial_number","location","status","software_license","antivirus_status","patch_status","assigned_to","notes"]
    upd, params = [], []
    for f in fields:
        if f in data: upd.append(f"{f}=?"); params.append(data[f])
    if upd:
        params.append(asset_id)
        query_db(f"UPDATE it_assets SET {', '.join(upd)} WHERE id=?", params, commit=True)
    return jsonify(row_to_dict(query_db("SELECT * FROM it_assets WHERE id=?", (asset_id,), one=True))), 200


# ============================================================
# LICENSES
# ============================================================

@app.route("/api/licenses", methods=["GET"])
@require_auth
def get_licenses():
    rows = query_db("SELECT * FROM licenses ORDER BY expiry_date ASC")
    summary = {
        "total":       query_db("SELECT COUNT(*) as c FROM licenses", one=True)["c"],
        "valid":       query_db("SELECT COUNT(*) as c FROM licenses WHERE status='valid'", one=True)["c"],
        "expired":     query_db("SELECT COUNT(*) as c FROM licenses WHERE status='expired'", one=True)["c"],
        "renewal_due": query_db("SELECT COUNT(*) as c FROM licenses WHERE status='renewal_due'", one=True)["c"],
        "suspended":   query_db("SELECT COUNT(*) as c FROM licenses WHERE status='suspended'", one=True)["c"],
    }
    return jsonify({"licenses": rows_to_list(rows), "summary": summary}), 200

@app.route("/api/licenses", methods=["POST"])
@require_company
def create_license():
    data = request.get_json() or {}
    for req in ["license_name","license_type","authority","issue_date","expiry_date"]:
        if req not in data: return jsonify({"error": f"'{req}' required"}), 400
    new_id = "LIC" + uuid.uuid4().hex[:6].upper()
    now = datetime.now().isoformat()
    query_db("INSERT INTO licenses (id,license_name,license_type,authority,license_number,issue_date,expiry_date,status,renewal_reminder,documents,notes,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
             (new_id, data["license_name"], data["license_type"], data["authority"],
              data.get("license_number",""), data["issue_date"], data["expiry_date"],
              data.get("status","valid"), int(data.get("renewal_reminder",30)),
              data.get("documents",""), data.get("notes",""), now), commit=True)
    return jsonify(row_to_dict(query_db("SELECT * FROM licenses WHERE id=?", (new_id,), one=True))), 201

@app.route("/api/licenses/<lic_id>", methods=["PUT"])
@require_company
def update_license(lic_id):
    if not query_db("SELECT id FROM licenses WHERE id=?", (lic_id,), one=True):
        return jsonify({"error": "Not found"}), 404
    data = request.get_json() or {}
    fields = ["license_name","license_type","authority","license_number","issue_date","expiry_date","status","renewal_reminder","documents","notes"]
    upd, params = [], []
    for f in fields:
        if f in data: upd.append(f"{f}=?"); params.append(data[f])
    if upd:
        params.append(lic_id)
        query_db(f"UPDATE licenses SET {', '.join(upd)} WHERE id=?", params, commit=True)
    return jsonify(row_to_dict(query_db("SELECT * FROM licenses WHERE id=?", (lic_id,), one=True))), 200

@app.route("/api/licenses/<lic_id>", methods=["DELETE"])
@require_company
def delete_license(lic_id):
    if not query_db("SELECT id FROM licenses WHERE id=?", (lic_id,), one=True):
        return jsonify({"error": "Not found"}), 404
    query_db("DELETE FROM licenses WHERE id=?", (lic_id,), commit=True)
    return jsonify({"message": "Deleted"}), 200


# ============================================================
# COMPLIANCE
# ============================================================

@app.route("/api/compliance", methods=["GET"])
@require_auth
def get_compliance():
    rows = query_db("SELECT * FROM compliance ORDER BY due_date ASC")
    return jsonify(rows_to_list(rows)), 200

@app.route("/api/compliance", methods=["POST"])
@require_company
def create_compliance():
    data = request.get_json() or {}
    for req in ["requirement","framework","owner","due_date"]:
        if req not in data: return jsonify({"error": f"'{req}' required"}), 400
    new_id = "c" + uuid.uuid4().hex[:8]
    query_db("INSERT INTO compliance (id,requirement,framework,owner,due_date,status,score,authority,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
             (new_id, data["requirement"], data["framework"], data["owner"], data["due_date"],
              "review", 0, data.get("authority",""), datetime.now().isoformat()), commit=True)
    return jsonify(row_to_dict(query_db("SELECT * FROM compliance WHERE id=?", (new_id,), one=True))), 201

@app.route("/api/compliance/<item_id>", methods=["PUT"])
@require_company
def update_compliance(item_id):
    if not query_db("SELECT id FROM compliance WHERE id=?", (item_id,), one=True):
        return jsonify({"error": "Not found"}), 404
    data = request.get_json() or {}
    fields = ["requirement","framework","owner","due_date","status","score","authority"]
    upd, params = [], []
    for f in fields:
        if f in data: upd.append(f"{f}=?"); params.append(data[f])
    if upd:
        params.append(item_id)
        query_db(f"UPDATE compliance SET {', '.join(upd)} WHERE id=?", params, commit=True)
    return jsonify(row_to_dict(query_db("SELECT * FROM compliance WHERE id=?", (item_id,), one=True))), 200

@app.route("/api/compliance/<item_id>", methods=["DELETE"])
@require_company
def delete_compliance(item_id):
    if not query_db("SELECT id FROM compliance WHERE id=?", (item_id,), one=True):
        return jsonify({"error": "Not found"}), 404
    query_db("DELETE FROM compliance WHERE id=?", (item_id,), commit=True)
    return jsonify({"message": "Deleted"}), 200


# ============================================================
# USERS
# ============================================================

@app.route("/api/users", methods=["GET"])
@require_company
def get_users():
    rows  = query_db("SELECT * FROM users ORDER BY created_at DESC")
    users = [safe_user(row_to_dict(r)) for r in rows]
    return jsonify({"users": users, "total": len(users)}), 200

@app.route("/api/users/<user_id>", methods=["DELETE"])
@require_company
def delete_user(user_id):
    if user_id == request.current_user["id"]:
        return jsonify({"error": "Cannot delete own account"}), 400
    row = query_db("SELECT * FROM users WHERE id=?", (user_id,), one=True)
    if not row: return jsonify({"error": "Not found"}), 404
    query_db("DELETE FROM users WHERE id=?", (user_id,), commit=True)
    log_activity("user_removed", f"User {row['fname']} {row['lname']} removed", "", "red")
    return jsonify({"message": "Deleted"}), 200


# ============================================================
# REPORTS
# ============================================================

@app.route("/api/reports", methods=["GET"])
@require_auth
def get_reports():
    return jsonify(rows_to_list(query_db("SELECT * FROM reports ORDER BY date DESC"))), 200

@app.route("/api/reports", methods=["POST"])
@require_company
def create_report():
    data = request.get_json() or {}
    if not data.get("title") or not data.get("type"):
        return jsonify({"error": "title and type required"}), 400
    new_id = "r" + uuid.uuid4().hex[:8]
    query_db("INSERT INTO reports (id,title,type,date,status,size,created_at) VALUES (?,?,?,?,?,?,?)",
             (new_id, data["title"], data["type"], datetime.now().strftime("%Y-%m-%d"),
              "pending", "—", datetime.now().isoformat()), commit=True)
    return jsonify(row_to_dict(query_db("SELECT * FROM reports WHERE id=?", (new_id,), one=True))), 201


# ============================================================
# ANALYTICS
# ============================================================

@app.route("/api/analytics/summary", methods=["GET"])
@require_auth
def analytics_summary():
    dept_rows = query_db("""
        SELECT department, COUNT(*) as total,
               SUM(CASE WHEN status='pass' THEN 1 ELSE 0 END) as passed,
               ROUND(AVG(risk_score),1) as avg_risk
        FROM audits GROUP BY department ORDER BY total DESC
    """)
    cat_rows = query_db("""
        SELECT category, COUNT(*) as total,
               SUM(CASE WHEN status='fail' THEN 1 ELSE 0 END) as failed
        FROM audits GROUP BY category ORDER BY total DESC
    """)
    month_rows = query_db("""
        SELECT SUBSTR(date,1,7) as month, COUNT(*) as total,
               SUM(CASE WHEN status='pass' THEN 1 ELSE 0 END) as passed,
               SUM(CASE WHEN status='fail' THEN 1 ELSE 0 END) as failed
        FROM audits GROUP BY month ORDER BY month ASC
    """)
    return jsonify({
        "departments": rows_to_list(dept_rows),
        "categories": rows_to_list(cat_rows),
        "monthly": rows_to_list(month_rows)
    }), 200


# ============================================================
# CHATBOT
# ============================================================

@app.route("/api/chatbot", methods=["POST"])
@require_auth
def chatbot():
    data    = request.get_json() or {}
    message = data.get("message","").lower()
    user    = request.current_user

    total   = query_db("SELECT COUNT(*) as c FROM audits", one=True)["c"]
    passed  = query_db("SELECT COUNT(*) as c FROM audits WHERE status='pass'", one=True)["c"]
    failed  = query_db("SELECT COUNT(*) as c FROM audits WHERE status='fail'", one=True)["c"]
    warn    = query_db("SELECT COUNT(*) as c FROM audits WHERE status='warning'", one=True)["c"]
    comp    = query_db("SELECT AVG(score) as a FROM compliance", one=True)["a"] or 0
    expired_lic = query_db("SELECT COUNT(*) as c FROM licenses WHERE status='expired'", one=True)["c"]
    expired_inv = query_db("SELECT COUNT(*) as c FROM inventory_audits WHERE status='expired'", one=True)["c"]
    gst_issues  = query_db("SELECT COUNT(*) as c FROM gst_compliance WHERE status IN ('overdue','under_review')", one=True)["c"]

    if any(w in message for w in ["hello","hi ","hey","namaste"]):
        reply = (f"👋 வணக்கம் <strong>{user['fname']}</strong>! I'm AuditBot for Tamil Nadu Departmental Store Audit.<br>"
                 "Ask me about GST, inventory, licenses, HR compliance, IT assets, or overall audit status.")
    elif any(w in message for w in ["summary","overview","dashboard","status"]):
        pass_rate = round(passed/total*100,1) if total else 0
        reply = (f"📊 <strong>Store Audit Summary (Live from DB):</strong><br>"
                 f"• Total Audits: <strong>{total}</strong> | Pass Rate: <strong>{pass_rate}%</strong><br>"
                 f"• Failed: <strong>{failed}</strong> | Warnings: <strong>{warn}</strong><br>"
                 f"• Expired Licenses: <strong>{expired_lic}</strong> (immediate action!)<br>"
                 f"• Expired Stock on Shelf: <strong>{expired_inv}</strong><br>"
                 f"• GST Issues: <strong>{gst_issues}</strong><br>"
                 f"• Overall Compliance: <strong>{round(comp,1)}%</strong>")
    elif any(w in message for w in ["gst","filing","tax","return","itc"]):
        rows  = query_db("SELECT period,filing_type,status,tax_amount FROM gst_compliance LIMIT 5")
        lines = "<br>".join([f"• {r['period']} {r['filing_type']}: <strong>{r['status'].upper()}</strong> — ₹{r['tax_amount']:,.0f}" for r in rows])
        reply = (f"📋 <strong>GST Filings (Live):</strong><br>{lines}<br><br>"
                 f"Overdue/Review count: <strong>{gst_issues}</strong>")
    elif any(w in message for w in ["inventory","stock","expired","shrinkage","shortage"]):
        rows  = query_db("SELECT item_name,status,discrepancy FROM inventory_audits WHERE status!='match' LIMIT 5")
        lines = "<br>".join([f"• {r['item_name']}: <strong>{r['status'].upper()}</strong> (diff: {r['discrepancy']})" for r in rows])
        reply = (f"📦 <strong>Inventory Issues (Live):</strong><br>{lines}<br><br>"
                 f"Expired on shelf: <strong>{expired_inv}</strong> — Remove immediately!")
    elif any(w in message for w in ["license","fssai","trade","fire","noc","weights","plastic"]):
        rows  = query_db("SELECT license_name,status,expiry_date FROM licenses ORDER BY expiry_date ASC LIMIT 6")
        lines = "<br>".join([f"• {r['license_name']}: <strong>{r['status'].upper()}</strong> (exp: {r['expiry_date']})" for r in rows])
        reply = (f"📜 <strong>License Status (Live):</strong><br>{lines}<br><br>"
                 f"Expired: <strong>{expired_lic}</strong> | Action required!")
    elif any(w in message for w in ["hr","employee","pf","esi","payroll","staff","wage"]):
        issues = query_db("SELECT COUNT(*) as c FROM hr_compliance WHERE pf_status!='active' OR esi_status!='active'", one=True)["c"]
        total_emp = query_db("SELECT COUNT(*) as c FROM hr_compliance", one=True)["c"]
        reply = (f"👥 <strong>HR Compliance (Live):</strong><br>"
                 f"• Total Employees: <strong>{total_emp}</strong><br>"
                 f"• PF/ESI Issues: <strong>{issues}</strong><br>"
                 f"• Training Pending: <strong>"
                 f"{query_db('SELECT COUNT(*) as c FROM hr_compliance WHERE training_status=?', ('pending',), one=True)['c']}"
                 f"</strong>")
    elif any(w in message for w in ["it","pos","server","cctv","network","wifi","computer","software","patch"]):
        faulty = query_db("SELECT COUNT(*) as c FROM it_assets WHERE status IN ('faulty','under_review','maintenance')", one=True)["c"]
        outdated = query_db("SELECT COUNT(*) as c FROM it_assets WHERE patch_status='outdated'", one=True)["c"]
        total_it = query_db("SELECT COUNT(*) as c FROM it_assets", one=True)["c"]
        reply = (f"💻 <strong>IT Assets (Live):</strong><br>"
                 f"• Total Assets: <strong>{total_it}</strong><br>"
                 f"• Faulty/Issues: <strong>{faulty}</strong><br>"
                 f"• Outdated Patches: <strong>{outdated}</strong><br>"
                 f"• PCI-DSS Risk: Check POS terminals!")
    elif any(w in message for w in ["fail","critical","issue","problem","urgent"]):
        rows  = query_db("SELECT id,title,department FROM audits WHERE status='fail' LIMIT 5")
        lines = "<br>".join([f"• {r['id']}: {r['department']} — {r['title']}" for r in rows])
        reply = (f"⚠️ <strong>Failed Audits ({failed} total):</strong><br>{lines}")
    elif any(w in message for w in ["compliance","sox","gdpr","pci","iso"]):
        fw_rows = query_db("SELECT framework, ROUND(AVG(score),1) as a FROM compliance GROUP BY framework")
        lines   = "<br>".join([f"• {r['framework']}: <strong>{r['a']}%</strong>" for r in fw_rows])
        reply   = (f"🛡 <strong>Framework Compliance (Live):</strong><br>{lines}<br>Overall avg: <strong>{round(comp,1)}%</strong>")
    elif any(w in message for w in ["help","what can","commands"]):
        reply = ("I can answer with <strong>live DB data</strong>:<br>"
                 "• 📊 Dashboard summary<br>• 📋 GST filings status<br>"
                 "• 📦 Inventory issues<br>• 📜 License renewals<br>"
                 "• 👥 HR/PF/ESI compliance<br>• 💻 IT asset status<br>"
                 "• ⚠️ Failed audits<br>• Type <em>help</em> anytime")
    else:
        reply = ("Not sure about that. Try: <em>gst status</em>, <em>inventory issues</em>, "
                 "<em>license renewals</em>, <em>hr compliance</em>, or <em>summary</em>.")

    return jsonify({"reply": reply}), 200


# ============================================================
# PROFILE
# ============================================================

@app.route("/api/profile", methods=["PUT"])
@require_auth
def update_profile():
    data = request.get_json() or {}
    user = request.current_user
    upd, params = [], []
    for f in ["fname","lname","company"]:
        if f in data: upd.append(f"{f}=?"); params.append(data[f])
    if upd:
        params.append(user["id"])
        query_db(f"UPDATE users SET {', '.join(upd)} WHERE id=?", params, commit=True)
    return jsonify(safe_user(row_to_dict(query_db("SELECT * FROM users WHERE id=?", (user["id"],), one=True)))), 200

@app.route("/api/profile/password", methods=["PUT"])
@require_auth
def change_password():
    data = request.get_json() or {}
    old_pw = data.get("old_password",""); new_pw = data.get("new_password","")
    if not old_pw or not new_pw: return jsonify({"error": "Both passwords required"}), 400
    if len(new_pw) < 8: return jsonify({"error": "Min 8 chars"}), 400
    user = request.current_user
    if not check_password_hash(user["password_hash"], old_pw):
        return jsonify({"error": "Current password incorrect"}), 401
    query_db("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new_pw), user["id"]), commit=True)
    return jsonify({"message": "Password updated"}), 200


# ============================================================
# HEALTH + STATIC
# ============================================================

@app.route("/")
def serve_frontend():
    return send_from_directory(".", "audit_dashboard.html")

@app.route("/api/health", methods=["GET"])
def health():
    try:
        count = query_db("SELECT COUNT(*) as c FROM users", one=True)["c"]
        db_ok = f"ok ({count} users)"
    except Exception as e:
        db_ok = f"error: {e}"
    return jsonify({"status": "healthy", "version": "3.0.0-store",
                    "database": os.path.abspath(DATABASE), "db_status": db_ok,
                    "timestamp": datetime.now().isoformat()}), 200

@app.errorhandler(404)
def not_found(e): return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(e): return jsonify({"error": "Internal server error", "detail": str(e)}), 500


if __name__ == "__main__":
    print("=" * 65)
    print("  🏪  AuditPro — Departmental Store Edition  v3.0")
    print("  📍  Tamil Nadu, India")
    print("=" * 65)
    init_db()
    print()
    print(f"  Database: {os.path.abspath(DATABASE)}")
    print(f"  URL:      http://localhost:5000")
    print()
    print("  Demo Credentials:")
    print("  ┌────────────────────────────────────────────────┐")
    print("  │  User:    user@demo.com    / demo1234          │")
    print("  │  Company: company@demo.com / demo1234          │")
    print("  └────────────────────────────────────────────────┘")
    print()
    print("  API Endpoints:")
    print("  POST  /api/auth/login           Sign in")
    print("  GET   /api/dashboard/metrics    Live KPIs")
    print("  GET/POST /api/audits            Audit records")
    print("  GET/POST /api/inventory         Inventory audit")
    print("  GET/POST /api/gst               GST compliance")
    print("  GET/POST /api/hr                HR compliance")
    print("  GET/POST /api/it-assets         IT asset register")
    print("  GET/POST /api/licenses          License tracker")
    print("  GET/POST /api/compliance        Regulatory compliance")
    print("  GET/POST /api/reports           Reports")
    print("  GET      /api/users             User management")
    print("  POST     /api/chatbot           AuditBot (live DB)")
    print("  GET      /api/analytics/summary Analytics")
    print("=" * 65)
    app.run(debug=True, host="0.0.0.0", port=5000)