import csv
import hmac
import io
import os
import secrets
import time
from datetime import timedelta
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

from .phonebook import FIELDS, parse_xml, validate, xml_for
from .phones import Phone, PhoneError, subnets_from
from .store import Store


def create_app(folder=None):
    store = Store(folder or os.environ.get("DATA_DIR", "/data"))
    password = os.environ.get("APP_PASSWORD", "")
    if os.environ.get("APP_PASSWORD_FILE"):
        password = Path(os.environ["APP_PASSWORD_FILE"]).read_text().strip()
    if password:
        if len(password) < 12:
            raise RuntimeError("APP_PASSWORD must contain at least 12 characters.")
        store.configure_password(password)
    if not store.get("password_hash"):
        raise RuntimeError("Set APP_PASSWORD or APP_PASSWORD_FILE for the first startup.")
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=store.get("session_key"),
        MAX_CONTENT_LENGTH=2_000_000,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    )
    app.extensions["store"] = store
    app.extensions["phone_factory"] = Phone

    @app.template_filter("when")
    def when(value):
        if not value:
            return "Never"
        from datetime import datetime, timezone

        return datetime.fromtimestamp(value, timezone.utc).strftime("%d %b %H:%M UTC")

    @app.context_processor
    def globals_for_template():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(32)
        return {"csrf": session["csrf"]}

    @app.before_request
    def protect():
        if request.endpoint == "health":
            return
        if request.method == "POST":
            if not hmac.compare_digest(session.get("csrf", ""), request.form.get("csrf", "")):
                abort(400, "Session expired. Reload the page and try again.")
            if not session.get("csrf"):
                abort(400)
        if request.endpoint not in ("login", "static") and not session.get("authenticated"):
            return redirect(url_for("login"))

    @app.after_request
    def headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(413)
    def too_large(error):
        return render_template(
            "error.html", message="The upload is too large. Maximum size is 2 MB."
        ), 413

    @app.get("/health")
    def health():
        ready = time.time() - store.get("heartbeat", 0) < 180
        return {"status": "ok" if ready else "worker unavailable"}, 200 if ready else 503

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            ip = request.remote_addr or "unknown"
            now = time.time()
            with store.db() as db:
                row = db.execute("SELECT * FROM login_attempts WHERE ip=?", (ip,)).fetchone()
                if row and now - row["since"] < 300 and row["attempts"] >= 5:
                    return render_template(
                        "login.html", error="Too many attempts. Try again in five minutes."
                    ), 429
                if check_password_hash(
                    store.get("password_hash"), request.form.get("password", "")
                ):
                    db.execute("DELETE FROM login_attempts WHERE ip=?", (ip,))
                    session.clear()
                    session["authenticated"] = True
                    session["csrf"] = secrets.token_hex(32)
                    session.permanent = True
                    return redirect(url_for("index"))
                count = row["attempts"] + 1 if row and now - row["since"] < 300 else 1
                since = row["since"] if count > 1 else now
                db.execute(
                    "INSERT OR REPLACE INTO login_attempts VALUES (?,?,?)", (ip, count, since)
                )
            return render_template("login.html", error="Incorrect password."), 401
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            contacts=store.contacts(),
            deleted=store.contacts(True),
            revision=store.get("revision"),
            initialized=store.get("initialized"),
            phones=store.phones(),
        )

    @app.post("/contacts/<action>")
    def contacts(action):
        try:
            revision = int(request.form["revision"])
            if action in ("add", "edit"):
                values = validate(request.form)
                if action == "edit":
                    values += (int(request.form["id"]),)
                if action == "add" and len(store.contacts()) >= 1000:
                    raise ValueError("The directory can contain at most 1,000 contacts.")
            elif action in ("delete", "restore"):
                values = (int(request.form["id"]),)
                if action == "restore" and len(store.contacts()) >= 1000:
                    raise ValueError("The directory can contain at most 1,000 contacts.")
                if (
                    action == "delete"
                    and len(store.contacts()) == 1
                    and request.form.get("confirm_empty") != "yes"
                ):
                    raise ValueError(
                        "Removing the last contact clears enrolled phones. Confirm this in the remove dialog."
                    )
            else:
                abort(404)
            store.change(action, values, revision)
            flash("Directory saved. Enrolled phones will update in the background.", "success")
        except (ValueError, KeyError):
            # Validation messages contain no credentials or device responses.
            import sys

            flash(str(sys.exc_info()[1]), "error")
        return redirect(url_for("index"))

    @app.post("/import")
    def import_file():
        try:
            file = request.files.get("file")
            if not file:
                raise ValueError("Choose an XML or CSV file.")
            raw = file.read(2_000_001)
            if len(raw) > 2_000_000:
                raise ValueError("File exceeds 2 MB.")
            if file.filename.lower().endswith(".xml"):
                rows = parse_xml(raw)
            elif file.filename.lower().endswith(".csv"):
                rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
                if not rows or not set(FIELDS).issubset(rows[0]):
                    raise ValueError("CSV headers must be name, office, mobile, other.")
                for row in rows:
                    for key in FIELDS:
                        if row[key] and row[key].startswith(("'=", "'+", "'-", "'@")):
                            row[key] = row[key][1:]
            else:
                raise ValueError("Choose a Yealink XML export or CSV file.")
            if not rows or len(rows) > 1000:
                raise ValueError("Import between 1 and 1,000 contacts.")
            values = [validate(r) for r in rows]
            store.change("replace", values, int(request.form["revision"]))
            flash("Directory imported. Previous contacts remain available to restore.", "success")
        except Exception as error:
            flash(
                str(error)
                if isinstance(error, ValueError)
                else "Could not read the directory file.",
                "error",
            )
        return redirect(url_for("index"))

    @app.get("/export.xml")
    def export_xml():
        return send_file(
            io.BytesIO(xml_for(store.contacts())),
            mimetype="application/xml",
            as_attachment=True,
            download_name="contact.xml",
        )

    @app.get("/export.csv")
    def export_csv():
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(FIELDS)
        for row in store.contacts():
            # Prevent spreadsheet formulas when opening exported CSV.
            writer.writerow(
                [
                    "'" + row[k] if row[k].startswith(("=", "+", "-", "@")) else row[k]
                    for k in FIELDS
                ]
            )
        return send_file(
            io.BytesIO(buffer.getvalue().encode()),
            mimetype="text/csv",
            as_attachment=True,
            download_name="directory.csv",
        )

    @app.route("/settings", methods=["GET", "POST"])
    def settings():
        if request.method == "POST":
            try:
                networks = subnets_from(request.form.get("subnets", ""))
                username = request.form.get("username", "").strip()
                if not username or len(username) > 64:
                    raise ValueError("Enter the phone administrator username.")
                with store.db() as db:
                    store.set_in(db, "subnets", networks)
                    store.set_in(db, "username", username)
                    if request.form.get("phone_password"):
                        store.set_in(
                            db,
                            "phone_password",
                            store.cipher.encrypt(request.form["phone_password"].encode()).decode(),
                        )
                    store.set_in(db, "scan_requested", True)
                flash("Settings saved. Phone discovery is queued.", "success")
            except ValueError as error:
                flash(str(error), "error")
            return redirect(url_for("settings"))
        return render_template(
            "settings.html",
            subnets="\n".join(store.get("subnets")),
            username=store.get("username"),
            password_set=bool(store.get("phone_password")),
        )

    @app.get("/phones")
    def phones():
        return render_template(
            "phones.html",
            phones=store.phones(),
            events=store.events(),
            initialized=store.get("initialized"),
            last_scan=store.get("last_scan"),
        )

    @app.post("/scan")
    def scan():
        store.put("scan_requested", True)
        flash("Discovery queued. It can take about a minute per subnet.", "success")
        return redirect(url_for("phones"))

    @app.post("/phones/<int:phone_id>/<action>")
    def phone_action(phone_id, action):
        row = next((r for r in store.phones() if r["id"] == phone_id), None)
        if not row:
            abort(404)
        if action == "enroll":
            if not store.password():
                flash("Add the phone administrator password in Settings first.", "error")
            else:
                phone = app.extensions["phone_factory"](row["ip"], row["fingerprint"])
                try:
                    identity = phone.login(store.get("username"), store.password())
                    with store.db() as db:
                        duplicate = db.execute(
                            "SELECT id FROM phones WHERE mac=? AND enrolled=1 AND id<>?",
                            (identity["mac"], phone_id),
                        ).fetchone()
                        if duplicate:
                            raise ValueError(
                                "This MAC address is already enrolled with another certificate. Pause it first."
                            )
                        db.execute(
                            "UPDATE phones SET enrolled=1,mac=?,firmware=?,status='Queued',"
                            "halted=0,retry_at=0 WHERE id=?",
                            (identity["mac"], identity["firmware"], phone_id),
                        )
                    store.event(phone_id, "Phone enrolled; observed certificate trusted")
                    flash(
                        "Phone enrolled. Updates begin once the master directory is initialized.",
                        "success",
                    )
                except Exception as error:
                    flash(
                        str(error)
                        if isinstance(error, (ValueError, PhoneError))
                        else "Enrollment failed. Check credentials, connectivity and firmware.",
                        "error",
                    )
                finally:
                    phone.logout()
        elif action in ("pause", "retry"):
            with store.db() as db:
                if action == "pause":
                    db.execute(
                        "UPDATE phones SET enrolled=0,status='Paused' WHERE id=?", (phone_id,)
                    )
                else:
                    db.execute(
                        "UPDATE phones SET halted=0,retry_at=0,checked=0,status='Queued',error='' WHERE id=?",
                        (phone_id,),
                    )
            flash(
                "Phone paused." if action == "pause" else "Verification and retry queued.",
                "success",
            )
        else:
            abort(404)
        return redirect(url_for("phones"))

    @app.get("/backups/<int:event_id>")
    def backup(event_id):
        with store.db() as db:
            row = db.execute("SELECT backup FROM events WHERE id=?", (event_id,)).fetchone()
        if not row or not row["backup"]:
            abort(404)
        path = (store.folder / row["backup"]).resolve()
        if not path.is_relative_to(store.folder.resolve()) or not path.is_file():
            abort(404)
        return send_file(path, as_attachment=True, download_name=path.name)

    @app.get("/status")
    def status():
        return {
            "phones": [
                {k: r[k] for k in ("id", "ip", "status", "error", "revision", "enrolled")}
                for r in store.phones()
            ],
            "revision": store.get("revision"),
            "worker": time.time() - store.get("heartbeat", 0) < 180,
        }

    return app
