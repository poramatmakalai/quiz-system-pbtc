#!/usr/bin/env python3
"""
Local Quiz Management System
Player Website + Admin Dashboard
Flask + SQLite - Fully local, no internet required after install
"""

import os
import sqlite3
import json
import hashlib
import secrets
import csv
import io
from datetime import datetime, timedelta
from functools import wraps
from contextlib import contextmanager

from flask import (
    Flask, render_template, request, jsonify, session, redirect,
    url_for, flash, send_file, g, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# App Config
# ---------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "database", "quiz.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "images")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "svg"}

def _load_or_create_secret():
    """Persist secret key so sessions survive restarts; file is local-only."""
    secret_path = os.path.join(BASE_DIR, "database", ".secret_key")
    os.makedirs(os.path.dirname(secret_path), exist_ok=True)
    env_key = (os.environ.get("QUIZ_SECRET_KEY") or "").strip()
    if env_key:
        return env_key
    if os.path.isfile(secret_path):
        with open(secret_path, "r", encoding="utf-8") as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_hex(32)
    with open(secret_path, "w", encoding="utf-8") as f:
        f.write(key)
    try:
        os.chmod(secret_path, 0o600)
    except OSError:
        pass
    return key


app = Flask(__name__)
app.secret_key = _load_or_create_secret()
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=4)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_NAME"] = "quiz_session"
# Only send Secure cookie when HTTPS is actually used
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("QUIZ_HTTPS", "").lower() in ("1", "true", "yes")

os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Login rate limiting (in-memory; resets on restart)
_login_attempts = {}
_LOGIN_MAX_FAILS = 5
_LOGIN_LOCK_SECONDS = 300  # 5 minutes


def _client_ip():
    # Prefer direct peer; ignore X-Forwarded-For unless explicitly trusted
    return (request.remote_addr or "unknown").strip()


def _login_locked(ip):
    info = _login_attempts.get(ip)
    if not info:
        return False
    fails, locked_until = info
    if locked_until and datetime.utcnow() < locked_until:
        return True
    if locked_until and datetime.utcnow() >= locked_until:
        _login_attempts.pop(ip, None)
    return False


def _register_login_failure(ip):
    fails, locked_until = _login_attempts.get(ip, (0, None))
    fails += 1
    if fails >= _LOGIN_MAX_FAILS:
        locked_until = datetime.utcnow() + timedelta(seconds=_LOGIN_LOCK_SECONDS)
        fails = 0
    _login_attempts[ip] = (fails, locked_until)


def _clear_login_failures(ip):
    _login_attempts.pop(ip, None)


@app.after_request
def set_security_headers(response):
    """Baseline security headers for a LAN-exposed local server."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Local HTTP often; avoid breaking inline scripts in admin templates
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------------------
# Database Helpers
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@contextmanager
def db_cursor():
    db = get_db()
    cur = db.cursor()
    try:
        yield cur
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        cur.close()


def init_db():
    """Create all tables and seed initial data if empty."""
    with app.app_context():
        db = get_db()
        cur = db.cursor()

        # admin_users
        cur.execute("""
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                last_login TEXT
            )
        """)

        # categories
        cur.execute("""
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                icon TEXT DEFAULT '',
                is_active INTEGER NOT NULL DEFAULT 1,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
            )
        """)
        # Migration: add sort_order if upgrading older DB
        try:
            cur.execute("SELECT sort_order FROM categories LIMIT 1")
        except sqlite3.OperationalError:
            cur.execute("ALTER TABLE categories ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0")
            cur.execute("UPDATE categories SET sort_order = id WHERE sort_order = 0 OR sort_order IS NULL")

        # questions
        cur.execute("""
            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category_id INTEGER NOT NULL,
                question_text TEXT NOT NULL,
                image_path TEXT DEFAULT '',
                explanation TEXT DEFAULT '',
                points INTEGER NOT NULL DEFAULT 1,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
            )
        """)

        # question_options
        cur.execute("""
            CREATE TABLE IF NOT EXISTS question_options (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question_id INTEGER NOT NULL,
                option_text TEXT NOT NULL,
                is_correct INTEGER NOT NULL DEFAULT 0,
                sort_order INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
            )
        """)

        # game_settings (single row)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS game_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                game_name TEXT NOT NULL DEFAULT 'เกมตอบคำถาม วิทยาลัยเทคนิคเพชรบุรี',
                logo_path TEXT DEFAULT '/static/images/pbtc-logo.png',
                welcome_message TEXT DEFAULT 'ยินดีต้อนรับสู่ระบบเกมตอบคำถาม วิทยาลัยเทคนิคเพชรบุรี',
                questions_per_round INTEGER NOT NULL DEFAULT 10,
                time_per_question INTEGER NOT NULL DEFAULT 20,
                pass_percentage REAL NOT NULL DEFAULT 70.0,
                show_explanation INTEGER NOT NULL DEFAULT 1,
                enable_sound INTEGER NOT NULL DEFAULT 0,
                start_message TEXT DEFAULT 'พร้อมเริ่มเกมแล้ว!',
                end_message TEXT DEFAULT 'จบเกมแล้ว ขอบคุณที่ร่วมสนุก',
                pass_message TEXT DEFAULT 'ยินดีด้วย! คุณผ่านเกณฑ์แล้ว',
                fail_message TEXT DEFAULT 'เสียใจด้วย คุณยังไม่ผ่านเกณฑ์ ลองใหม่อีกครั้งนะ',
                insufficient_questions_policy TEXT DEFAULT 'use_available',
                updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
            )
        """)

        # rewards
        cur.execute("""
            CREATE TABLE IF NOT EXISTS rewards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                image_path TEXT DEFAULT '',
                min_percentage REAL NOT NULL DEFAULT 70.0,
                is_active INTEGER NOT NULL DEFAULT 1,
                message TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
            )
        """)

        # game_sessions
        cur.execute("""
            CREATE TABLE IF NOT EXISTS game_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                player_name TEXT DEFAULT '',
                category_id INTEGER NOT NULL,
                started_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                finished_at TEXT,
                status TEXT NOT NULL DEFAULT 'playing',
                current_question_index INTEGER NOT NULL DEFAULT 0,
                time_per_question INTEGER NOT NULL,
                total_points INTEGER NOT NULL DEFAULT 0,
                earned_points INTEGER NOT NULL DEFAULT 0,
                correct_count INTEGER NOT NULL DEFAULT 0,
                wrong_count INTEGER NOT NULL DEFAULT 0,
                timeout_count INTEGER NOT NULL DEFAULT 0,
                percentage REAL DEFAULT 0,
                is_passed INTEGER DEFAULT 0,
                reward_id INTEGER,
                FOREIGN KEY (category_id) REFERENCES categories(id),
                FOREIGN KEY (reward_id) REFERENCES rewards(id)
            )
        """)

        # game_session_questions (the actual questions selected for a session)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS game_session_questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                question_id INTEGER NOT NULL,
                sort_order INTEGER NOT NULL,
                points INTEGER NOT NULL,
                FOREIGN KEY (session_id) REFERENCES game_sessions(id) ON DELETE CASCADE,
                FOREIGN KEY (question_id) REFERENCES questions(id)
            )
        """)

        # game_answers
        cur.execute("""
            CREATE TABLE IF NOT EXISTS game_answers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                question_id INTEGER NOT NULL,
                selected_option_id INTEGER,
                is_correct INTEGER NOT NULL DEFAULT 0,
                is_timeout INTEGER NOT NULL DEFAULT 0,
                points_earned INTEGER NOT NULL DEFAULT 0,
                answered_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                FOREIGN KEY (session_id) REFERENCES game_sessions(id) ON DELETE CASCADE,
                FOREIGN KEY (question_id) REFERENCES questions(id),
                FOREIGN KEY (selected_option_id) REFERENCES question_options(id)
            )
        """)

        # game_results (summary, can be derived but kept for history)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS game_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL UNIQUE,
                player_name TEXT DEFAULT '',
                category_id INTEGER NOT NULL,
                category_name TEXT NOT NULL,
                total_points INTEGER NOT NULL,
                earned_points INTEGER NOT NULL,
                percentage REAL NOT NULL,
                correct_count INTEGER NOT NULL,
                wrong_count INTEGER NOT NULL,
                timeout_count INTEGER NOT NULL,
                is_passed INTEGER NOT NULL,
                reward_name TEXT DEFAULT '',
                played_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                FOREIGN KEY (session_id) REFERENCES game_sessions(id) ON DELETE CASCADE,
                FOREIGN KEY (category_id) REFERENCES categories(id)
            )
        """)

        db.commit()

        # Seed admin if none
        cur.execute("SELECT COUNT(*) FROM admin_users")
        if cur.fetchone()[0] == 0:
            pw_hash = generate_password_hash("admin123")
            cur.execute(
                "INSERT INTO admin_users (username, password_hash) VALUES (?, ?)",
                ("admin", pw_hash)
            )
            print("Created default admin: username=admin password=admin123")

        # Seed settings if none
        cur.execute("SELECT COUNT(*) FROM game_settings")
        if cur.fetchone()[0] == 0:
            cur.execute("INSERT INTO game_settings (id) VALUES (1)")

        # Columns added for kiosk / PR (safe on existing databases)
        extra_cols = {
            "promo_title": "TEXT DEFAULT 'ข่าวสารวิทยาลัย'",
            "promo_message": "TEXT DEFAULT 'สมัครเรียนวิทยาลัยเทคนิคเพชรบุรี สแกน QR เพื่อดูรายละเอียดเพิ่มเติม'",
            "qr_url": "TEXT DEFAULT 'https://pbtc.ac.th/'",
            "qr_label": "TEXT DEFAULT 'สแกนเพื่อเข้าเว็บวิทยาลัย'",
            "show_qr_home": "INTEGER NOT NULL DEFAULT 1",
            "show_qr_result": "INTEGER NOT NULL DEFAULT 1",
            "font_scale": "REAL NOT NULL DEFAULT 1.22",
        }
        existing = {r[1] for r in cur.execute("PRAGMA table_info(game_settings)").fetchall()}
        for col, ddl in extra_cols.items():
            if col not in existing:
                cur.execute(f"ALTER TABLE game_settings ADD COLUMN {col} {ddl}")

        # Seed sample data if no categories
        cur.execute("SELECT COUNT(*) FROM categories")
        if cur.fetchone()[0] == 0:
            seed_sample_data(cur)
            db.commit()
            print("Seeded sample categories and questions")

        db.commit()


def seed_sample_data(cur):
    """Insert 3 categories with several questions each."""
    categories = [
        ("วิทยาศาสตร์", "คำถามเกี่ยวกับวิทยาศาสตร์ทั่วไป", "🔬"),
        ("ประวัติศาสตร์", "คำถามเกี่ยวกับประวัติศาสตร์ไทยและโลก", "📜"),
        ("เทคโนโลยี", "คำถามเกี่ยวกับคอมพิวเตอร์และเทคโนโลยี", "💻"),
    ]
    cat_ids = []
    for name, desc, icon in categories:
        cur.execute(
            "INSERT INTO categories (name, description, icon, is_active) VALUES (?, ?, ?, 1)",
            (name, desc, icon)
        )
        cat_ids.append(cur.lastrowid)

    # Science questions
    science_qs = [
        ("ดาวเคราะห์ดวงใดอยู่ใกล้ดวงอาทิตย์ที่สุด?", ["ดาวพุธ", "ดาวศุกร์", "โลก", "ดาวอังคาร"], 0, 1, "ดาวพุธเป็นดาวเคราะห์ที่อยู่ใกล้ดวงอาทิตย์ที่สุด"),
        ("ธาตุใดมีสัญลักษณ์ทางเคมีว่า H?", ["ฮีเลียม", "ไฮโดรเจน", "คาร์บอน", "ออกซิเจน"], 1, 1, "H ย่อมาจาก Hydrogen"),
        ("แสงเดินทางเร็วที่สุดในตัวกลางใด?", ["น้ำ", "อากาศ", "สุญญากาศ", "แก้ว"], 2, 2, "แสงเดินทางเร็วที่สุดในสุญญากาศประมาณ 3×10^8 m/s"),
        ("อวัยวะใดทำหน้าที่สูบฉีดเลือด?", ["ปอด", "ตับ", "หัวใจ", "ไต"], 2, 1, "หัวใจทำหน้าที่สูบฉีดเลือดไปทั่วร่างกาย"),
        ("สารใดเป็นกรด?", ["NaOH", "HCl", "NaCl", "KOH"], 1, 2, "HCl คือกรดไฮโดรคลอริก"),
        ("พืชสังเคราะห์แสงได้เพราะมีสารใด?", ["คลอโรฟิลล์", "ฮีโมโกลบิน", "เมลานิน", "เคราติน"], 0, 1, "คลอโรฟิลล์ช่วยจับแสงเพื่อสังเคราะห์แสง"),
        ("หน่วยวัดแรงในระบบ SI คืออะไร?", ["จูล", "นิวตัน", "วัตต์", "ปาสคาล"], 1, 1, "แรงวัดเป็นนิวตัน (N)"),
        ("DNA ย่อมาจากอะไร?", ["Deoxyribonucleic Acid", "Dinucleic Acid", "Deoxy Nuclear Acid", "Dual Nucleic Acid"], 0, 2, "DNA = Deoxyribonucleic Acid"),
        ("อุณหภูมิที่น้ำเดือดที่ระดับน้ำทะเลคือกี่องศาเซลเซียส?", ["90", "100", "110", "120"], 1, 1, "น้ำเดือดที่ 100°C ที่ความดันมาตรฐาน"),
        ("ก๊าซใดที่พืชดูดซึมเพื่อสังเคราะห์แสง?", ["ออกซิเจน", "ไนโตรเจน", "คาร์บอนไดออกไซด์", "ไฮโดรเจน"], 2, 1, "พืชใช้ CO2 ในการสังเคราะห์แสง"),
        ("ดาวเคราะห์ดวงใดใหญ่ที่สุดในระบบสุริยะ?", ["โลก", "ดาวเสาร์", "ดาวพฤหัสบดี", "ดาวยูเรนัส"], 2, 1, "ดาวพฤหัสบดีเป็นดาวเคราะห์ที่ใหญ่ที่สุด"),
        ("เลือดสีแดงเพราะมีสารใด?", ["คลอโรฟิลล์", "ฮีโมโกลบิน", "เมลานิน", "บิลิรูบิน"], 1, 1, "ฮีโมโกลบินทำให้เลือดมีสีแดง"),
    ]

    # History questions
    history_qs = [
        ("กรุงศรีอยุธยาถูกพม่าเผาในปี พ.ศ. ใด?", ["2310", "2320", "2300", "2315"], 0, 2, "กรุงศรีอยุธยาเสียแก่พม่าเมื่อ พ.ศ. 2310"),
        ("ใครเป็นผู้สถาปนากรุงรัตนโกสินทร์?", ["พระเจ้าตากสิน", "พระบาทสมเด็จพระพุทธยอดฟ้าจุฬาโลก", "พระนเรศวร", "พระเจ้าอู่ทอง"], 1, 1, "รัชกาลที่ 1 ทรงสถาปนากรุงรัตนโกสินทร์"),
        ("สงครามโลกครั้งที่ 2 สิ้นสุดในปี ค.ศ. ใด?", ["1943", "1944", "1945", "1946"], 2, 1, "สงครามโลกครั้งที่ 2 สิ้นสุดปี 1945"),
        ("พระมหากษัตริย์องค์ใดทรงสร้างวัดพระแก้ว?", ["รัชกาลที่ 1", "รัชกาลที่ 3", "รัชกาลที่ 4", "รัชกาลที่ 5"], 0, 1, "รัชกาลที่ 1 ทรงสร้างวัดพระศรีรัตนศาสดาราม"),
        ("ใครค้นพบอเมริกาในปี 1492?", ["มาเจลแลน", "โคลัมบัส", "วาสโก ดา กามา", "คุก"], 1, 1, "คริสโตเฟอร์ โคลัมบัส"),
        ("เหตุการณ์ 14 ตุลาเกิดขึ้นในปี พ.ศ. ใด?", ["2516", "2519", "2535", "2549"], 0, 2, "เหตุการณ์ 14 ตุลาคม 2516"),
        ("ใครเป็นประธานาธิบดีคนแรกของสหรัฐอเมริกา?", ["อับราฮัม ลินคอล์น", "จอร์จ วอชิงตัน", "โทมัส เจฟเฟอร์สัน", "จอห์น อดัมส์"], 1, 1, "จอร์จ วอชิงตัน"),
        ("กำแพงเมืองจีนสร้างขึ้นในสมัยราชวงศ์ใดเป็นหลัก?", ["ชิง", "หมิง", "ถัง", "ฮั่น"], 1, 2, "กำแพงเมืองจีนส่วนใหญ่สร้างและซ่อมในสมัยราชวงศ์หมิง"),
        ("พระเจ้าอเล็กซานเดอร์มหาราชมาจากประเทศใด?", ["โรม", "กรีก", "เปอร์เซีย", "อียิปต์"], 1, 1, "มาจากมาซิโดเนีย (กรีกโบราณ)"),
        ("วันที่ประเทศไทยเปลี่ยนแปลงการปกครองเป็นประชาธิปไตยคือ?", ["24 มิถุนายน 2475", "10 ธันวาคม 2475", "5 ธันวาคม 2475", "1 เมษายน 2475"], 0, 2, "24 มิถุนายน พ.ศ. 2475"),
    ]

    # Tech questions
    tech_qs = [
        ("ภาษาโปรแกรมใดใช้สำหรับพัฒนาเว็บฝั่ง Server ได้หลายแบบ?", ["HTML", "CSS", "Python", "Photoshop"], 2, 1, "Python สามารถใช้กับ Flask, Django ฯลฯ"),
        ("HTTP ย่อมาจากอะไร?", ["HyperText Transfer Protocol", "High Transfer Text Protocol", "Hyper Transfer Protocol", "Home Text Transfer Protocol"], 0, 1, "HyperText Transfer Protocol"),
        ("หน่วยความจำที่เก็บข้อมูลชั่วคราวขณะเปิดเครื่องเรียกว่าอะไร?", ["HDD", "SSD", "RAM", "ROM"], 2, 1, "RAM = Random Access Memory"),
        ("ใครเป็นผู้ก่อตั้งบริษัท Microsoft?", ["Steve Jobs", "Bill Gates", "Elon Musk", "Mark Zuckerberg"], 1, 1, "Bill Gates และ Paul Allen"),
        ("ภาษาที่ใช้เขียนหน้าเว็บโครงสร้างหลักคืออะไร?", ["Python", "Java", "HTML", "SQL"], 2, 1, "HTML เป็นภาษามาร์กอัปสำหรับโครงสร้างหน้าเว็บ"),
        ("ฐานข้อมูลแบบ Relational ใช้ภาษาใดในการ Query?", ["NoSQL", "SQL", "GraphQL", "REST"], 1, 1, "SQL = Structured Query Language"),
        ("Git ใช้สำหรับอะไร?", ["ออกแบบ UI", "ควบคุมเวอร์ชันของโค้ด", "เขียนเอกสาร", "ทดสอบความเร็ว"], 1, 1, "Git เป็นระบบ Version Control"),
        ("IPv4 มีกี่บิต?", ["16", "32", "64", "128"], 1, 2, "IPv4 ใช้ 32 บิต"),
        ("CSS ย่อมาจากอะไร?", ["Computer Style Sheet", "Cascading Style Sheets", "Creative Style System", "Color Style Sheet"], 1, 1, "Cascading Style Sheets"),
        ("Framework ใดต่อไปนี้เป็นของ Python สำหรับสร้างเว็บ?", ["React", "Vue", "Flask", "Angular"], 2, 1, "Flask เป็น Python micro-framework"),
        ("หน่วยความจำที่เก็บข้อมูลถาวรแม้ปิดเครื่องคืออะไร?", ["RAM", "Cache", "ROM / Storage", "Register"], 2, 1, "Storage เช่น HDD/SSD เก็บข้อมูลถาวร"),
        ("API ย่อมาจากอะไร?", ["Application Programming Interface", "Advanced Program Integration", "Automated Process Interface", "Application Process Input"], 0, 1, "Application Programming Interface"),
    ]

    def insert_questions(cat_id, qs_list):
        for q_text, options, correct_idx, points, expl in qs_list:
            cur.execute(
                """INSERT INTO questions (category_id, question_text, explanation, points, is_active)
                   VALUES (?, ?, ?, ?, 1)""",
                (cat_id, q_text, expl, points)
            )
            q_id = cur.lastrowid
            for i, opt in enumerate(options):
                cur.execute(
                    """INSERT INTO question_options (question_id, option_text, is_correct, sort_order)
                       VALUES (?, ?, ?, ?)""",
                    (q_id, opt, 1 if i == correct_idx else 0, i)
                )

    insert_questions(cat_ids[0], science_qs)
    insert_questions(cat_ids[1], history_qs)
    insert_questions(cat_ids[2], tech_qs)

    # Seed a default reward
    cur.execute(
        """INSERT INTO rewards (name, description, min_percentage, is_active, message)
           VALUES (?, ?, ?, 1, ?)""",
        ("รางวัลผู้ผ่านเกณฑ์", "คุณผ่านเกณฑ์คะแนนและมีสิทธิ์รับรางวัลจากผู้จัด", 70.0,
         "ยินดีด้วย! คุณผ่านเกณฑ์แล้ว")
    )


# ---------------------------------------------------------------------------
# Auth Helpers
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_id"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized", "message": "กรุณาเข้าสู่ระบบ"}), 401
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated


def get_current_admin():
    if not session.get("admin_id"):
        return None
    db = get_db()
    return db.execute("SELECT id, username FROM admin_users WHERE id = ?", (session["admin_id"],)).fetchone()


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_settings():
    db = get_db()
    row = db.execute("SELECT * FROM game_settings WHERE id = 1").fetchone()
    return dict(row) if row else {}


def row_to_dict(row):
    if row is None:
        return None
    return dict(row)


# ===========================================================================
# PLAYER ROUTES (Public)
# ===========================================================================

@app.route("/")
def index():
    return redirect(url_for("player_home"))


@app.route("/player")
@app.route("/player/")
def player_home():
    settings = get_settings()
    return render_template("player/index.html", settings=settings)


@app.route("/player/quiz")
def player_quiz():
    """Quiz page - requires active session."""
    session_id = session.get("game_session_id")
    if not session_id:
        return redirect(url_for("player_home"))
    settings = get_settings()
    return render_template("player/quiz.html", settings=settings, session_id=session_id)


@app.route("/player/result")
def player_result():
    session_id = request.args.get("session_id") or session.get("game_session_id")
    if not session_id:
        return redirect(url_for("player_home"))
    settings = get_settings()
    return render_template("player/result.html", settings=settings, session_id=session_id)


def public_display(settings):
    """Fields the player pages may show. Edited only from Admin."""
    return {
        "promo_title": settings.get("promo_title") or "",
        "promo_message": settings.get("promo_message") or "",
        "qr_url": (settings.get("qr_url") or "").strip(),
        "qr_label": settings.get("qr_label") or "",
        "show_qr_home": bool(settings.get("show_qr_home", 1)),
        "show_qr_result": bool(settings.get("show_qr_result", 1)),
        "enable_sound": bool(settings.get("enable_sound", 0)),
        "pass_message": settings.get("pass_message") or "",
        "fail_message": settings.get("fail_message") or "",
    }


@app.route("/api/qr.svg")
def api_qr_svg():
    """QR image for a URL configured in Admin. Offline, no external service."""
    import io
    import segno
    raw = (request.args.get("u") or "").strip()
    if not raw or len(raw) > 800:
        return jsonify({"error": "invalid_url"}), 400
    qr = segno.make(raw, error="m")
    buf = io.BytesIO()
    qr.save(buf, kind="svg", scale=6, border=2, dark="#005a87", light="#ffffff")
    return app.response_class(buf.getvalue(), mimetype="image/svg+xml")


# --- Player API ---

@app.route("/api/player/categories")
def api_player_categories():
    """List active categories available for players to choose."""
    db = get_db()
    settings = get_settings()
    questions_needed = settings.get("questions_per_round", 10)
    rows = db.execute("""
        SELECT c.id, c.name, c.description, c.icon, c.sort_order,
               (SELECT COUNT(*) FROM questions q
                WHERE q.category_id = c.id AND q.is_active = 1) as question_count
        FROM categories c
        WHERE c.is_active = 1
        ORDER BY c.sort_order ASC, c.id ASC
    """).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["has_enough"] = d["question_count"] >= questions_needed
        d["questions_per_round"] = questions_needed
        result.append(d)
    return jsonify({
        "categories": result,
        "questions_per_round": questions_needed,
        "time_per_question": settings.get("time_per_question", 20),
        "enable_sound": bool(settings.get("enable_sound", 0))
    })


@app.route("/api/player/start", methods=["POST"])
def api_player_start():
    """Start a new game for a player-selected category. Randomly picks N questions from that category."""
    data = request.get_json(silent=True) or {}
    player_name = (data.get("player_name") or "").strip()[:100]
    category_id = data.get("category_id")

    if not category_id:
        return jsonify({"error": "category_required", "message": "กรุณาเลือกหมวดหมู่"}), 400

    try:
        category_id = int(category_id)
    except (TypeError, ValueError):
        return jsonify({"error": "invalid_category", "message": "หมวดหมู่ไม่ถูกต้อง"}), 400

    db = get_db()
    settings = get_settings()
    questions_needed = settings.get("questions_per_round", 10)
    time_per_q = settings.get("time_per_question", 20)
    policy = settings.get("insufficient_questions_policy", "use_available")

    chosen = db.execute("""
        SELECT c.id, c.name, c.icon,
               (SELECT COUNT(*) FROM questions q WHERE q.category_id = c.id AND q.is_active = 1) as q_count
        FROM categories c
        WHERE c.id = ? AND c.is_active = 1
    """, (category_id,)).fetchone()

    if not chosen:
        return jsonify({"error": "category_not_found", "message": "ไม่พบหมวดหมู่ที่เลือก หรือหมวดหมู่นี้ถูกปิดใช้งาน"}), 400

    if chosen["q_count"] == 0:
        return jsonify({"error": "no_questions", "message": "หมวดหมู่นี้ยังไม่มีคำถามที่พร้อมเล่น"}), 400

    if chosen["q_count"] < questions_needed:
        if policy == "block":
            return jsonify({
                "error": "insufficient_questions",
                "message": f"หมวดนี้มีคำถามเพียง {chosen['q_count']} ข้อ แต่ระบบตั้งไว้ {questions_needed} ข้อต่อรอบ"
            }), 400
        # use_available: play with whatever is available
        questions_needed = chosen["q_count"]

    # Randomly select questions from this category only (no mixing)
    questions = db.execute("""
        SELECT id, points FROM questions
        WHERE category_id = ? AND is_active = 1
        ORDER BY RANDOM()
        LIMIT ?
    """, (category_id, questions_needed)).fetchall()

    if len(questions) == 0:
        return jsonify({"error": "no_questions", "message": "หมวดหมู่นี้ยังไม่มีคำถาม"}), 400

    total_points = sum(q["points"] for q in questions)
    category_name = chosen["name"]

    cur = db.cursor()
    cur.execute("""
        INSERT INTO game_sessions
        (player_name, category_id, status, time_per_question, total_points, current_question_index)
        VALUES (?, ?, 'playing', ?, ?, 0)
    """, (player_name, category_id, time_per_q, total_points))
    session_id = cur.lastrowid

    for i, q in enumerate(questions):
        cur.execute("""
            INSERT INTO game_session_questions (session_id, question_id, sort_order, points)
            VALUES (?, ?, ?, ?)
        """, (session_id, q["id"], i, q["points"]))

    db.commit()

    session["game_session_id"] = session_id
    session.permanent = True

    return jsonify({
        "success": True,
        "session_id": session_id,
        "category_id": category_id,
        "category_name": category_name,
        "category_icon": chosen["icon"] or "",
        "total_questions": len(questions),
        "time_per_question": time_per_q,
        "total_points": total_points,
        "player_name": player_name,
        "enable_sound": bool(settings.get("enable_sound", 0))
    })


@app.route("/api/player/question/<int:session_id>")
def api_player_question(session_id):
    """Get current question for a session. Correct answer is NEVER sent."""
    db = get_db()
    gs = db.execute("SELECT * FROM game_sessions WHERE id = ?", (session_id,)).fetchone()
    if not gs:
        return jsonify({"error": "not_found", "message": "ไม่พบรอบเกม"}), 404
    if gs["status"] != "playing":
        return jsonify({"error": "finished", "message": "เกมจบแล้ว", "redirect": "result"}), 400

    idx = gs["current_question_index"]
    total = db.execute(
        "SELECT COUNT(*) FROM game_session_questions WHERE session_id = ?", (session_id,)
    ).fetchone()[0]

    if idx >= total:
        return jsonify({"error": "finished", "message": "ตอบครบทุกข้อแล้ว", "redirect": "result"}), 400

    # Get the question for this index
    sq = db.execute("""
        SELECT gsq.question_id, gsq.points, q.question_text, q.image_path, q.explanation
        FROM game_session_questions gsq
        JOIN questions q ON q.id = gsq.question_id
        WHERE gsq.session_id = ? AND gsq.sort_order = ?
    """, (session_id, idx)).fetchone()

    if not sq:
        return jsonify({"error": "question_missing"}), 500

    # Check if already answered
    existing = db.execute(
        "SELECT id FROM game_answers WHERE session_id = ? AND question_id = ?",
        (session_id, sq["question_id"])
    ).fetchone()
    if existing:
        return jsonify({"error": "already_answered", "message": "ตอบข้อนี้ไปแล้ว"}), 400

    options = db.execute("""
        SELECT id, option_text, sort_order
        FROM question_options
        WHERE question_id = ?
        ORDER BY sort_order
    """, (sq["question_id"],)).fetchall()

    cat = db.execute("SELECT name, icon FROM categories WHERE id = ?", (gs["category_id"],)).fetchone()

    return jsonify({
        "session_id": session_id,
        "question_index": idx,
        "total_questions": total,
        "question_id": sq["question_id"],
        "question_text": sq["question_text"],
        "image_path": sq["image_path"] or "",
        "points": sq["points"],
        "options": [{"id": o["id"], "text": o["option_text"]} for o in options],
        "time_per_question": gs["time_per_question"],
        "category_name": cat["name"] if cat else "",
        "category_icon": cat["icon"] if cat else "",
        "player_name": gs["player_name"] or "",
        "earned_so_far": gs["earned_points"],
        "show_explanation": bool(get_settings().get("show_explanation", 1)),
        "enable_sound": bool(get_settings().get("enable_sound", 0))
    })


@app.route("/api/player/answer", methods=["POST"])
def api_player_answer():
    """Submit answer. Server validates everything."""
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id")
    question_id = data.get("question_id")
    option_id = data.get("option_id")  # None if timeout
    is_timeout = bool(data.get("is_timeout", False))
    client_time_left = data.get("time_left")  # optional, for logging only

    if not session_id or not question_id:
        return jsonify({"error": "invalid", "message": "ข้อมูลไม่ครบ"}), 400

    db = get_db()
    gs = db.execute("SELECT * FROM game_sessions WHERE id = ?", (session_id,)).fetchone()
    if not gs or gs["status"] != "playing":
        return jsonify({"error": "invalid_session"}), 400

    # Verify this question belongs to this session and is the current one
    sq = db.execute("""
        SELECT gsq.*, q.explanation
        FROM game_session_questions gsq
        JOIN questions q ON q.id = gsq.question_id
        WHERE gsq.session_id = ? AND gsq.question_id = ?
    """, (session_id, question_id)).fetchone()

    if not sq:
        return jsonify({"error": "question_not_in_session"}), 400

    if sq["sort_order"] != gs["current_question_index"]:
        return jsonify({"error": "not_current_question", "message": "ไม่ใช่คำถามปัจจุบัน"}), 400

    # Prevent double answer
    existing = db.execute(
        "SELECT id FROM game_answers WHERE session_id = ? AND question_id = ?",
        (session_id, question_id)
    ).fetchone()
    if existing:
        return jsonify({"error": "already_answered"}), 400

    is_correct = 0
    points_earned = 0
    correct_option_id = None
    correct_option_text = ""

    # Find correct option
    correct_opt = db.execute(
        "SELECT id, option_text FROM question_options WHERE question_id = ? AND is_correct = 1 LIMIT 1",
        (question_id,)
    ).fetchone()
    if correct_opt:
        correct_option_id = correct_opt["id"]
        correct_option_text = correct_opt["option_text"]

    if is_timeout or option_id is None:
        is_timeout = True
        is_correct = 0
        points_earned = 0
    else:
        # Validate option belongs to this question
        opt = db.execute(
            "SELECT id, is_correct FROM question_options WHERE id = ? AND question_id = ?",
            (option_id, question_id)
        ).fetchone()
        if not opt:
            return jsonify({"error": "invalid_option"}), 400
        is_correct = 1 if opt["is_correct"] else 0
        points_earned = sq["points"] if is_correct else 0

    # Record answer
    cur = db.cursor()
    cur.execute("""
        INSERT INTO game_answers
        (session_id, question_id, selected_option_id, is_correct, is_timeout, points_earned)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (session_id, question_id, option_id if not is_timeout else None, is_correct, 1 if is_timeout else 0, points_earned))

    # Update session stats
    new_earned = gs["earned_points"] + points_earned
    new_correct = gs["correct_count"] + (1 if is_correct else 0)
    new_wrong = gs["wrong_count"] + (0 if is_correct or is_timeout else 1)
    new_timeout = gs["timeout_count"] + (1 if is_timeout else 0)
    new_index = gs["current_question_index"] + 1

    total_q = db.execute(
        "SELECT COUNT(*) FROM game_session_questions WHERE session_id = ?", (session_id,)
    ).fetchone()[0]

    finished = new_index >= total_q
    status = "finished" if finished else "playing"

    cur.execute("""
        UPDATE game_sessions SET
            earned_points = ?,
            correct_count = ?,
            wrong_count = ?,
            timeout_count = ?,
            current_question_index = ?,
            status = ?,
            finished_at = CASE WHEN ? THEN datetime('now','localtime') ELSE finished_at END
        WHERE id = ?
    """, (new_earned, new_correct, new_wrong, new_timeout, new_index, status, finished, session_id))

    result_payload = {
        "is_correct": bool(is_correct),
        "is_timeout": is_timeout,
        "points_earned": points_earned,
        "correct_option_id": correct_option_id,
        "correct_option_text": correct_option_text,
        "explanation": sq["explanation"] or "",
        "show_explanation": bool(get_settings().get("show_explanation", 1)),
        "earned_points": new_earned,
        "total_points": gs["total_points"],
        "finished": finished,
        "next_index": new_index if not finished else None
    }

    if finished:
        # Finalize result
        percentage = round((new_earned / gs["total_points"] * 100) if gs["total_points"] > 0 else 0, 2)
        settings = get_settings()
        try:
            pass_pct = float(settings.get("pass_percentage") or 70)
        except (TypeError, ValueError):
            pass_pct = 70.0
        is_passed = 1 if percentage >= pass_pct else 0
        result_message = settings.get("pass_message") if is_passed else settings.get("fail_message")

        cur.execute("""
            UPDATE game_sessions SET
                percentage = ?, is_passed = ?, reward_id = NULL
            WHERE id = ?
        """, (percentage, is_passed, session_id))

        cat = db.execute("SELECT name FROM categories WHERE id = ?", (gs["category_id"],)).fetchone()
        cat_name = cat["name"] if cat else ""

        cur.execute("""
            INSERT INTO game_results
            (session_id, player_name, category_id, category_name, total_points, earned_points,
             percentage, correct_count, wrong_count, timeout_count, is_passed, reward_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id, gs["player_name"] or "", gs["category_id"], cat_name,
            gs["total_points"], new_earned, percentage, new_correct, new_wrong, new_timeout,
            is_passed, ""
        ))

        result_payload.update({
            "percentage": percentage,
            "is_passed": bool(is_passed),
            "reward_name": "",
            "reward_message": result_message or "",
            "pass_percentage": pass_pct,
            "correct_count": new_correct,
            "wrong_count": new_wrong,
            "timeout_count": new_timeout,
            "total_questions": new_correct + new_wrong + new_timeout,
        })

    db.commit()
    return jsonify(result_payload)


@app.route("/api/player/result/<int:session_id>")
def api_player_result(session_id):
    db = get_db()
    result = db.execute("SELECT * FROM game_results WHERE session_id = ?", (session_id,)).fetchone()
    if not result:
        # Maybe still finishing
        gs = db.execute("SELECT * FROM game_sessions WHERE id = ?", (session_id,)).fetchone()
        if not gs or gs["status"] != "finished":
            return jsonify({"error": "not_found"}), 404
        # Build from session
        cat = db.execute("SELECT name FROM categories WHERE id = ?", (gs["category_id"],)).fetchone()
        settings = get_settings()
        return jsonify({
            "session_id": session_id,
            "player_name": gs["player_name"] or "",
            "category_name": cat["name"] if cat else "",
            "total_points": gs["total_points"],
            "earned_points": gs["earned_points"],
            "percentage": gs["percentage"] or 0,
            "correct_count": gs["correct_count"],
            "wrong_count": gs["wrong_count"],
            "timeout_count": gs["timeout_count"],
            "is_passed": bool(gs["is_passed"]),
            "reward_name": "",
            "reward_message": settings.get("pass_message") if gs["is_passed"] else settings.get("fail_message"),
            "pass_message": settings.get("pass_message"),
            "fail_message": settings.get("fail_message"),
            "pass_percentage": settings.get("pass_percentage", 70),
            "total_questions": (gs["correct_count"] or 0) + (gs["wrong_count"] or 0) + (gs["timeout_count"] or 0),
            "enable_sound": bool(settings.get("enable_sound", 0)),
            **public_display(settings),
        })

    settings = get_settings()
    reward_msg = settings.get("pass_message", "") if result["is_passed"] else settings.get("fail_message", "")
    total_q = (result["correct_count"] or 0) + (result["wrong_count"] or 0) + (result["timeout_count"] or 0)
    return jsonify({
        "session_id": session_id,
        "player_name": result["player_name"] or "",
        "category_name": result["category_name"],
        "total_points": result["total_points"],
        "earned_points": result["earned_points"],
        "percentage": result["percentage"],
        "correct_count": result["correct_count"],
        "wrong_count": result["wrong_count"],
        "timeout_count": result["timeout_count"],
        "total_questions": total_q,
        "is_passed": bool(result["is_passed"]),
        "reward_name": "",
        "reward_message": reward_msg,
        "pass_message": settings.get("pass_message"),
        "fail_message": settings.get("fail_message"),
        "pass_percentage": settings.get("pass_percentage", 70),
        "enable_sound": bool(settings.get("enable_sound", 0)),
        **public_display(settings),
    })


# ===========================================================================
# ADMIN ROUTES
# ===========================================================================

@app.route("/admin")
@app.route("/admin/")
def admin_root():
    if session.get("admin_id"):
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("admin_login"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_id"):
        return redirect(url_for("admin_dashboard"))

    error = None
    if request.method == "POST":
        ip = _client_ip()
        if _login_locked(ip):
            error = "ลองเข้าสู่ระบบบ่อยเกินไป กรุณารอ 5 นาทีแล้วลองใหม่"
            return render_template("admin/login.html", error=error)

        username = (request.form.get("username") or "").strip()[:80]
        password = request.form.get("password") or ""
        # Constant-time style: always run a hash check path when possible
        db = get_db()
        user = db.execute("SELECT * FROM admin_users WHERE username = ?", (username,)).fetchone()
        ok = False
        if user:
            ok = check_password_hash(user["password_hash"], password)
        else:
            # Dummy hash verify to reduce timing oracle on missing user
            check_password_hash(
                "pbkdf2:sha256:260000$dummy$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                password or "x",
            )

        if ok:
            _clear_login_failures(ip)
            session.clear()
            session["admin_id"] = user["id"]
            session["admin_username"] = user["username"]
            session.permanent = True
            db.execute(
                "UPDATE admin_users SET last_login = datetime('now','localtime') WHERE id = ?",
                (user["id"],)
            )
            db.commit()
            return redirect(url_for("admin_dashboard"))

        _register_login_failure(ip)
        error = "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"
    return render_template("admin/login.html", error=error)


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    return render_template("admin/dashboard.html", admin=get_current_admin())


@app.route("/admin/categories")
@login_required
def admin_categories():
    return render_template("admin/categories.html", admin=get_current_admin())


@app.route("/admin/questions")
@login_required
def admin_questions():
    return render_template("admin/questions.html", admin=get_current_admin())


@app.route("/admin/settings")
@login_required
def admin_settings():
    return render_template("admin/settings.html", admin=get_current_admin())



@app.route("/admin/history")
@login_required
def admin_history():
    return render_template("admin/history.html", admin=get_current_admin())


@app.route("/admin/account")
@login_required
def admin_account():
    return render_template("admin/account.html", admin=get_current_admin())


# --- Admin API ---

@app.route("/api/admin/dashboard")
@login_required
def api_admin_dashboard():
    db = get_db()
    stats = {
        "total_categories": db.execute("SELECT COUNT(*) FROM categories").fetchone()[0],
        "active_categories": db.execute("SELECT COUNT(*) FROM categories WHERE is_active = 1").fetchone()[0],
        "total_questions": db.execute("SELECT COUNT(*) FROM questions").fetchone()[0],
        "active_questions": db.execute("SELECT COUNT(*) FROM questions WHERE is_active = 1").fetchone()[0],
        "total_sessions": db.execute("SELECT COUNT(*) FROM game_sessions").fetchone()[0],
        "finished_sessions": db.execute("SELECT COUNT(*) FROM game_sessions WHERE status = 'finished'").fetchone()[0],
        "total_players": db.execute("SELECT COUNT(DISTINCT player_name) FROM game_sessions WHERE player_name != ''").fetchone()[0],
        "passed_count": db.execute("SELECT COUNT(*) FROM game_results WHERE is_passed = 1").fetchone()[0],
        "failed_count": db.execute("SELECT COUNT(*) FROM game_results WHERE is_passed = 0").fetchone()[0],
    }
    recent = db.execute("""
        SELECT gr.*, c.icon
        FROM game_results gr
        LEFT JOIN categories c ON c.id = gr.category_id
        ORDER BY gr.played_at DESC LIMIT 10
    """).fetchall()
    stats["recent"] = [dict(r) for r in recent]
    return jsonify(stats)


# Categories CRUD
@app.route("/api/admin/categories", methods=["GET"])
@login_required
def api_categories_list():
    db = get_db()
    rows = db.execute("""
        SELECT c.*,
               (SELECT COUNT(*) FROM questions q WHERE q.category_id = c.id) as question_count,
               (SELECT COUNT(*) FROM questions q WHERE q.category_id = c.id AND q.is_active = 1) as active_question_count
        FROM categories c
        ORDER BY c.sort_order ASC, c.id ASC
    """).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/categories", methods=["POST"])
@login_required
def api_categories_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name_required", "message": "กรุณาระบุชื่อหมวดหมู่"}), 400
    description = (data.get("description") or "").strip()
    icon = (data.get("icon") or "").strip()[:10]
    is_active = 1 if data.get("is_active", True) else 0
    db = get_db()
    cur = db.cursor()
    # Default sort_order = max + 1 (appear at end)
    row = cur.execute("SELECT COALESCE(MAX(sort_order), 0) FROM categories").fetchone()
    sort_order = int(data.get("sort_order") if data.get("sort_order") is not None else (row[0] + 1))
    cur.execute(
        "INSERT INTO categories (name, description, icon, is_active, sort_order) VALUES (?, ?, ?, ?, ?)",
        (name, description, icon, is_active, sort_order)
    )
    db.commit()
    return jsonify({"success": True, "id": cur.lastrowid})


@app.route("/api/admin/categories/<int:cat_id>", methods=["PUT"])
@login_required
def api_categories_update(cat_id):
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name_required"}), 400
    description = (data.get("description") or "").strip()
    icon = (data.get("icon") or "").strip()[:10]
    is_active = 1 if data.get("is_active", True) else 0
    sort_order = data.get("sort_order")
    try:
        sort_order = int(sort_order) if sort_order is not None else 0
    except (TypeError, ValueError):
        sort_order = 0

    db = get_db()
    cur = db.cursor()
    cur.execute("""
        UPDATE categories SET name=?, description=?, icon=?, is_active=?, sort_order=?,
        updated_at=datetime('now','localtime') WHERE id=?
    """, (name, description, icon, is_active, sort_order, cat_id))
    if cur.rowcount == 0:
        return jsonify({"error": "not_found"}), 404
    db.commit()
    return jsonify({"success": True})


@app.route("/api/admin/categories/<int:cat_id>/move", methods=["POST"])
@login_required
def api_categories_move(cat_id):
    """Swap sort_order with neighbor: direction = 'up' | 'down'."""
    data = request.get_json(silent=True) or {}
    direction = (data.get("direction") or "").strip().lower()
    if direction not in ("up", "down"):
        return jsonify({"error": "invalid_direction"}), 400

    db = get_db()
    rows = db.execute(
        "SELECT id, sort_order FROM categories ORDER BY sort_order ASC, id ASC"
    ).fetchall()
    ids = [r["id"] for r in rows]
    if cat_id not in ids:
        return jsonify({"error": "not_found"}), 404
    idx = ids.index(cat_id)
    swap_idx = idx - 1 if direction == "up" else idx + 1
    if swap_idx < 0 or swap_idx >= len(ids):
        return jsonify({"success": True, "message": "already_at_edge"})

    a_id, b_id = ids[idx], ids[swap_idx]
    a_order = rows[idx]["sort_order"]
    b_order = rows[swap_idx]["sort_order"]
    # If equal sort_order, assign sequential then swap
    if a_order == b_order:
        for i, r in enumerate(rows):
            db.execute("UPDATE categories SET sort_order = ? WHERE id = ?", (i + 1, r["id"]))
        a_order, b_order = idx + 1, swap_idx + 1

    cur = db.cursor()
    cur.execute("UPDATE categories SET sort_order = ? WHERE id = ?", (b_order, a_id))
    cur.execute("UPDATE categories SET sort_order = ? WHERE id = ?", (a_order, b_id))
    db.commit()
    return jsonify({"success": True})


@app.route("/api/admin/categories/<int:cat_id>", methods=["DELETE"])
@login_required
def api_categories_delete(cat_id):
    db = get_db()
    # Check if used in sessions
    used = db.execute(
        "SELECT COUNT(*) FROM game_sessions WHERE category_id = ?", (cat_id,)
    ).fetchone()[0]
    cur = db.cursor()
    if used > 0:
        # Soft approach: deactivate instead of hard delete if history exists
        # But user asked for delete with confirmation - we still allow cascade
        pass
    cur.execute("DELETE FROM categories WHERE id = ?", (cat_id,))
    if cur.rowcount == 0:
        return jsonify({"error": "not_found"}), 404
    db.commit()
    return jsonify({"success": True})


# Questions CRUD
@app.route("/api/admin/questions", methods=["GET"])
@login_required
def api_questions_list():
    category_id = request.args.get("category_id", type=int)
    search = (request.args.get("search") or "").strip()
    active_only = request.args.get("active_only")

    db = get_db()
    sql = """
        SELECT q.*, c.name as category_name,
               (SELECT COUNT(*) FROM question_options o WHERE o.question_id = q.id) as option_count
        FROM questions q
        JOIN categories c ON c.id = q.category_id
        WHERE 1=1
    """
    params = []
    if category_id:
        sql += " AND q.category_id = ?"
        params.append(category_id)
    if search:
        sql += " AND q.question_text LIKE ?"
        params.append(f"%{search}%")
    if active_only == "1":
        sql += " AND q.is_active = 1"
    sql += " ORDER BY q.id DESC"

    rows = db.execute(sql, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/questions/<int:q_id>", methods=["GET"])
@login_required
def api_question_detail(q_id):
    db = get_db()
    q = db.execute("SELECT * FROM questions WHERE id = ?", (q_id,)).fetchone()
    if not q:
        return jsonify({"error": "not_found"}), 404
    options = db.execute(
        "SELECT * FROM question_options WHERE question_id = ? ORDER BY sort_order", (q_id,)
    ).fetchall()
    data = dict(q)
    data["options"] = [dict(o) for o in options]
    return jsonify(data)


@app.route("/api/admin/questions", methods=["POST"])
@login_required
def api_questions_create():
    data = request.get_json(silent=True) or {}
    category_id = data.get("category_id")
    question_text = (data.get("question_text") or "").strip()
    explanation = (data.get("explanation") or "").strip()
    points = data.get("points", 1)
    is_active = 1 if data.get("is_active", True) else 0
    options = data.get("options") or []
    image_path = (data.get("image_path") or "").strip()

    if not category_id:
        return jsonify({"error": "category_required", "message": "กรุณาเลือกหมวดหมู่"}), 400
    if not question_text:
        return jsonify({"error": "text_required", "message": "กรุณากรอกข้อความคำถาม"}), 400
    if not isinstance(points, int) or points < 1:
        return jsonify({"error": "invalid_points", "message": "คะแนนต้องเป็นจำนวนเต็มบวก"}), 400
    if len(options) < 2:
        return jsonify({"error": "min_options", "message": "ต้องมีตัวเลือกอย่างน้อย 2 ตัวเลือก"}), 400
    if len(options) > 6:
        return jsonify({"error": "max_options", "message": "ตัวเลือกได้สูงสุด 6 ตัวเลือก"}), 400

    correct_count = sum(1 for o in options if o.get("is_correct"))
    if correct_count != 1:
        return jsonify({"error": "one_correct", "message": "ต้องเลือกคำตอบที่ถูกต้องเพียง 1 ข้อ"}), 400

    for o in options:
        if not (o.get("option_text") or "").strip():
            return jsonify({"error": "empty_option", "message": "ตัวเลือกต้องไม่ว่าง"}), 400

    db = get_db()
    # Verify category exists
    if not db.execute("SELECT id FROM categories WHERE id = ?", (category_id,)).fetchone():
        return jsonify({"error": "category_not_found"}), 400

    cur = db.cursor()
    cur.execute("""
        INSERT INTO questions (category_id, question_text, image_path, explanation, points, is_active)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (category_id, question_text, image_path, explanation, points, is_active))
    q_id = cur.lastrowid

    for i, o in enumerate(options):
        cur.execute("""
            INSERT INTO question_options (question_id, option_text, is_correct, sort_order)
            VALUES (?, ?, ?, ?)
        """, (q_id, o["option_text"].strip(), 1 if o.get("is_correct") else 0, i))

    db.commit()
    return jsonify({"success": True, "id": q_id})


@app.route("/api/admin/questions/<int:q_id>", methods=["PUT"])
@login_required
def api_questions_update(q_id):
    data = request.get_json(silent=True) or {}
    category_id = data.get("category_id")
    question_text = (data.get("question_text") or "").strip()
    explanation = (data.get("explanation") or "").strip()
    points = data.get("points", 1)
    is_active = 1 if data.get("is_active", True) else 0
    options = data.get("options") or []
    image_path = (data.get("image_path") or "").strip()

    if not category_id or not question_text:
        return jsonify({"error": "required_fields"}), 400
    if not isinstance(points, int) or points < 1:
        return jsonify({"error": "invalid_points"}), 400
    if len(options) < 2 or len(options) > 6:
        return jsonify({"error": "options_count"}), 400
    if sum(1 for o in options if o.get("is_correct")) != 1:
        return jsonify({"error": "one_correct"}), 400

    db = get_db()
    if not db.execute("SELECT id FROM questions WHERE id = ?", (q_id,)).fetchone():
        return jsonify({"error": "not_found"}), 404

    cur = db.cursor()
    cur.execute("""
        UPDATE questions SET category_id=?, question_text=?, image_path=?, explanation=?,
        points=?, is_active=?, updated_at=datetime('now','localtime') WHERE id=?
    """, (category_id, question_text, image_path, explanation, points, is_active, q_id))

    # Replace options
    cur.execute("DELETE FROM question_options WHERE question_id = ?", (q_id,))
    for i, o in enumerate(options):
        cur.execute("""
            INSERT INTO question_options (question_id, option_text, is_correct, sort_order)
            VALUES (?, ?, ?, ?)
        """, (q_id, o["option_text"].strip(), 1 if o.get("is_correct") else 0, i))

    db.commit()
    return jsonify({"success": True})


@app.route("/api/admin/questions/<int:q_id>", methods=["DELETE"])
@login_required
def api_questions_delete(q_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM questions WHERE id = ?", (q_id,))
    if cur.rowcount == 0:
        return jsonify({"error": "not_found"}), 404
    db.commit()
    return jsonify({"success": True})


@app.route("/api/admin/questions/<int:q_id>/duplicate", methods=["POST"])
@login_required
def api_questions_duplicate(q_id):
    db = get_db()
    q = db.execute("SELECT * FROM questions WHERE id = ?", (q_id,)).fetchone()
    if not q:
        return jsonify({"error": "not_found"}), 404
    options = db.execute(
        "SELECT * FROM question_options WHERE question_id = ? ORDER BY sort_order", (q_id,)
    ).fetchall()

    cur = db.cursor()
    cur.execute("""
        INSERT INTO questions (category_id, question_text, image_path, explanation, points, is_active)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (q["category_id"], q["question_text"] + " (สำเนา)", q["image_path"], q["explanation"], q["points"], q["is_active"]))
    new_id = cur.lastrowid
    for o in options:
        cur.execute("""
            INSERT INTO question_options (question_id, option_text, is_correct, sort_order)
            VALUES (?, ?, ?, ?)
        """, (new_id, o["option_text"], o["is_correct"], o["sort_order"]))
    db.commit()
    return jsonify({"success": True, "id": new_id})


# Settings
@app.route("/api/admin/settings", methods=["GET"])
@login_required
def api_settings_get():
    return jsonify(get_settings())


@app.route("/api/admin/settings", methods=["PUT"])
@login_required
def api_settings_update():
    data = request.get_json(silent=True) or {}
    allowed = [
        "game_name", "logo_path", "welcome_message", "questions_per_round",
        "time_per_question", "pass_percentage", "show_explanation", "enable_sound",
        "start_message", "end_message", "pass_message", "fail_message",
        "insufficient_questions_policy",
        "promo_title", "promo_message", "qr_url", "qr_label",
        "show_qr_home", "show_qr_result",
    ]
    updates = []
    params = []
    for key in allowed:
        if key in data:
            updates.append(f"{key} = ?")
            val = data[key]
            if key in ("show_explanation", "enable_sound", "show_qr_home", "show_qr_result"):
                val = 1 if val else 0
            if key == "qr_url":
                val = (val or "").strip()[:800]
            if key == "pass_percentage":
                try:
                    val = max(0.0, min(100.0, float(val)))
                except (TypeError, ValueError):
                    val = 70.0
            if key in ("questions_per_round", "time_per_question"):
                try:
                    val = int(val)
                except (TypeError, ValueError):
                    continue
            params.append(val)

    if not updates:
        return jsonify({"error": "no_data"}), 400

    updates.append("updated_at = datetime('now','localtime')")
    sql = "UPDATE game_settings SET " + ", ".join(updates) + " WHERE id = 1"
    db = get_db()
    db.execute(sql, params)
    db.commit()
    return jsonify({"success": True, "settings": get_settings()})



# History
@app.route("/api/admin/history", methods=["GET"])
@login_required
def api_history_list():
    category_id = request.args.get("category_id", type=int)
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    search = (request.args.get("search") or "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), 100)

    db = get_db()
    sql = "SELECT * FROM game_results WHERE 1=1"
    params = []
    if category_id:
        sql += " AND category_id = ?"
        params.append(category_id)
    if date_from:
        sql += " AND date(played_at) >= date(?)"
        params.append(date_from)
    if date_to:
        sql += " AND date(played_at) <= date(?)"
        params.append(date_to)
    if search:
        sql += " AND (player_name LIKE ? OR category_name LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])

    count_sql = "SELECT COUNT(*) FROM (" + sql + ")"
    total = db.execute(count_sql, params).fetchone()[0]

    sql += " ORDER BY played_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, (page - 1) * per_page])
    rows = db.execute(sql, params).fetchall()

    return jsonify({
        "items": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page
    })


@app.route("/api/admin/history/<int:result_id>", methods=["DELETE"])
@login_required
def api_history_delete(result_id):
    db = get_db()
    # Get session_id first
    row = db.execute("SELECT session_id FROM game_results WHERE id = ?", (result_id,)).fetchone()
    if not row:
        return jsonify({"error": "not_found"}), 404
    session_id = row["session_id"]
    cur = db.cursor()
    cur.execute("DELETE FROM game_results WHERE id = ?", (result_id,))
    cur.execute("DELETE FROM game_sessions WHERE id = ?", (session_id,))
    db.commit()
    return jsonify({"success": True})


@app.route("/api/admin/history/export")
@login_required
def api_history_export():
    db = get_db()
    rows = db.execute("""
        SELECT player_name, category_name, earned_points, total_points, percentage,
               correct_count, wrong_count, timeout_count,
               CASE WHEN is_passed = 1 THEN 'ผ่าน' ELSE 'ไม่ผ่าน' END as status,
               reward_name, played_at
        FROM game_results ORDER BY played_at DESC
    """).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ชื่อผู้เล่น", "หมวดหมู่", "คะแนนที่ได้", "คะแนนเต็ม", "เปอร์เซ็นต์",
        "ถูก", "ผิด", "หมดเวลา", "สถานะ", "หมายเหตุ", "วันที่เล่น"
    ])
    for r in rows:
        writer.writerow([
            r["player_name"], r["category_name"], r["earned_points"], r["total_points"],
            r["percentage"], r["correct_count"], r["wrong_count"], r["timeout_count"],
            r["status"], r["reward_name"], r["played_at"]
        ])

    output.seek(0)
    # Add BOM for Excel Thai support
    mem = io.BytesIO()
    mem.write(b"\xef\xbb\xbf")
    mem.write(output.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(
        mem,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"quiz_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )


# Account
@app.route("/api/admin/change-password", methods=["POST"])
@login_required
def api_change_password():
    data = request.get_json(silent=True) or {}
    current = data.get("current_password") or ""
    new_pw = data.get("new_password") or ""
    if len(new_pw) < 6:
        return jsonify({"error": "too_short", "message": "รหัสผ่านใหม่ต้องมีอย่างน้อย 6 ตัวอักษร"}), 400

    db = get_db()
    user = db.execute("SELECT * FROM admin_users WHERE id = ?", (session["admin_id"],)).fetchone()
    if not user or not check_password_hash(user["password_hash"], current):
        return jsonify({"error": "wrong_password", "message": "รหัสผ่านปัจจุบันไม่ถูกต้อง"}), 400

    new_hash = generate_password_hash(new_pw)
    db.execute("UPDATE admin_users SET password_hash = ? WHERE id = ?", (new_hash, session["admin_id"]))
    db.commit()
    return jsonify({"success": True, "message": "เปลี่ยนรหัสผ่านสำเร็จ"})


# Simple image upload (optional)
@app.route("/api/admin/upload", methods=["POST"])
@login_required
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "no_file"}), 400
    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "empty"}), 400
    if f and allowed_file(f.filename):
        filename = secure_filename(f.filename)
        # Make unique
        name, ext = os.path.splitext(filename)
        filename = f"{name}_{secrets.token_hex(4)}{ext}"
        path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        f.save(path)
        return jsonify({"success": True, "path": f"/static/images/{filename}"})
    return jsonify({"error": "invalid_type"}), 400


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "not_found"}), 404
    return render_template("player/index.html", settings=get_settings()), 404


@app.errorhandler(500)
def server_error(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "server_error", "message": "เกิดข้อผิดพลาดภายในระบบ"}), 500
    return "Internal Server Error", 500


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "5000"))
    # Default debug OFF for safer LAN exposure; set FLASK_DEBUG=1 when developing
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    host = os.environ.get("HOST", "0.0.0.0")
    print("=" * 60)
    print("  Local Quiz Management System")
    print(f"  Player : http://127.0.0.1:{port}/player")
    print(f"  Admin  : http://127.0.0.1:{port}/admin")
    print(f"  Bind   : {host}:{port}  (LAN ใช้ IP เครื่องนี้)")
    print("  Default login: admin / admin123  ← ควรเปลี่ยนรหัสทันที")
    print("  Security: session HttpOnly + rate-limit login + security headers")
    print("=" * 60)
    app.run(host=host, port=port, debug=debug, use_reloader=False)
