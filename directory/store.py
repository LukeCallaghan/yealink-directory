import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.fernet import Fernet
from werkzeug.security import check_password_hash, generate_password_hash


class Store:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        os.chmod(self.folder, 0o700)
        self.path = self.folder / "directory.sqlite3"
        keyfile = self.folder / "key"
        if not keyfile.exists():
            with keyfile.open("xb") as f:
                f.write(Fernet.generate_key())
            os.chmod(keyfile, 0o600)
        self.cipher = Fernet(keyfile.read_bytes())
        with self.db() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS contacts (
                    id INTEGER PRIMARY KEY, name TEXT NOT NULL, office TEXT NOT NULL DEFAULT '',
                    mobile TEXT NOT NULL DEFAULT '', other TEXT NOT NULL DEFAULT '',
                    deleted INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS phones (
                    id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE,
                    ip TEXT NOT NULL, model TEXT NOT NULL, mac TEXT, firmware TEXT,
                    enrolled INTEGER NOT NULL DEFAULT 0, seen REAL NOT NULL,
                    checked REAL NOT NULL DEFAULT 0, revision INTEGER NOT NULL DEFAULT -1,
                    status TEXT NOT NULL DEFAULT 'Awaiting approval', error TEXT NOT NULL DEFAULT '',
                    halted INTEGER NOT NULL DEFAULT 0, retry_at REAL NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY, at REAL NOT NULL, phone_id INTEGER,
                    message TEXT NOT NULL, backup TEXT);
                CREATE TABLE IF NOT EXISTS login_attempts (
                    ip TEXT PRIMARY KEY, attempts INTEGER NOT NULL, since REAL NOT NULL);
            """)
            defaults = {
                "revision": 0,
                "initialized": False,
                "subnets": [],
                "username": "admin",
                "scan_requested": False,
                "heartbeat": 0,
                "last_scan": 0,
                "session_key": secrets.token_hex(32),
            }
            for key, value in defaults.items():
                db.execute("INSERT OR IGNORE INTO config VALUES (?,?)", (key, json.dumps(value)))

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def get(self, key, default=None):
        with self.db() as db:
            row = db.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else default

    def put(self, key, value):
        with self.db() as db:
            self.set_in(db, key, value)

    @staticmethod
    def set_in(db, key, value):
        db.execute("INSERT OR REPLACE INTO config VALUES (?,?)", (key, json.dumps(value)))

    def configure_password(self, password):
        current = self.get("password_hash")
        if not current or not check_password_hash(current, password):
            with self.db() as db:
                self.set_in(db, "password_hash", generate_password_hash(password))
                self.set_in(db, "session_key", secrets.token_hex(32))

    def contacts(self, deleted=False):
        with self.db() as db:
            return [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM contacts WHERE deleted=? ORDER BY name COLLATE NOCASE,id",
                    (int(deleted),),
                )
            ]

    def snapshot(self):
        with self.db() as db:
            db.execute("BEGIN")
            revision = json.loads(
                db.execute("SELECT value FROM config WHERE key='revision'").fetchone()[0]
            )
            rows = [dict(r) for r in db.execute("SELECT * FROM contacts WHERE deleted=0")]
            return revision, rows

    def change(self, action, values, revision):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            current = json.loads(
                db.execute("SELECT value FROM config WHERE key='revision'").fetchone()[0]
            )
            if current != revision:
                raise ValueError("The directory changed in another browser. Reload and try again.")
            if action == "add":
                db.execute(
                    "INSERT INTO contacts(name,office,mobile,other) VALUES (?,?,?,?)", values
                )
            elif action == "edit":
                if (
                    db.execute(
                        "UPDATE contacts SET name=?,office=?,mobile=?,other=? "
                        "WHERE id=? AND deleted=0",
                        values,
                    ).rowcount
                    != 1
                ):
                    raise ValueError("Contact no longer exists.")
            elif action in ("delete", "restore"):
                if (
                    db.execute(
                        "UPDATE contacts SET deleted=? WHERE id=?",
                        (int(action == "delete"), values[0]),
                    ).rowcount
                    != 1
                ):
                    raise ValueError("Contact no longer exists.")
            elif action == "replace":
                db.execute("UPDATE contacts SET deleted=1 WHERE deleted=0")
                db.executemany(
                    "INSERT INTO contacts(name,office,mobile,other) VALUES (?,?,?,?)", values
                )
            else:
                raise ValueError("Unknown change")
            if db.execute("SELECT COUNT(*) FROM contacts WHERE deleted=0").fetchone()[0] > 1000:
                raise ValueError("The directory can contain at most 1,000 contacts.")
            self.set_in(db, "revision", current + 1)
            self.set_in(db, "initialized", True)

    def password(self):
        value = self.get("phone_password")
        return self.cipher.decrypt(value.encode()).decode() if value else ""

    def phones(self):
        with self.db() as db:
            return [dict(r) for r in db.execute("SELECT * FROM phones ORDER BY enrolled DESC,ip")]

    def event(self, phone_id, message, backup=None):
        with self.db() as db:
            db.execute(
                "INSERT INTO events(at,phone_id,message,backup) VALUES (?,?,?,?)",
                (time.time(), phone_id, message, backup),
            )

    def events(self):
        with self.db() as db:
            return [dict(r) for r in db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 50")]

    def backup_database(self):
        folder = self.folder / "database-backups"
        folder.mkdir(exist_ok=True)
        target = folder / f"{time.time_ns()}.sqlite3"
        with self.db() as source, sqlite3.connect(target) as destination:
            source.backup(destination)
        # Contact history and per-phone backups remain; bound daily database snapshots.
        for old in sorted(folder.glob("*.sqlite3"))[:-14]:
            old.unlink()
