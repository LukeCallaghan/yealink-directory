import io
import json
import time

import pytest
from defusedxml.common import DefusedXmlException

from directory.phonebook import canonical, parse_xml, validate, xml_for
from directory.phones import BusyPhone, UnsafePhone, subnets_from
from directory.store import Store
from directory.web import create_app
from directory.worker import discover, sync_phone


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "data")


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_PASSWORD", "a sufficiently long test password")
    instance = create_app(tmp_path / "data")
    instance.config["TESTING"] = True
    return instance


def csrf(client):
    client.get("/login")
    with client.session_transaction() as session:
        return session["csrf"]


def login(client):
    return client.post(
        "/login", data={"csrf": csrf(client), "password": "a sufficiently long test password"}
    )


def post(client, url, **values):
    with client.session_transaction() as session:
        token = session["csrf"]
    return client.post(url, data={"csrf": token, **values}, follow_redirects=True)


def test_authentication_csrf_and_throttle(app):
    client = app.test_client()
    assert client.get("/export.xml").status_code == 302
    assert client.post("/contacts/add", data={"name": "x"}).status_code == 400
    token = csrf(client)
    for _ in range(5):
        assert client.post("/login", data={"csrf": token, "password": "wrong"}).status_code == 401
    assert client.post("/login", data={"csrf": token, "password": "wrong"}).status_code == 429
    with app.extensions["store"].db() as db:
        db.execute("DELETE FROM login_attempts")
    assert login(client).status_code == 302
    assert client.get("/").status_code == 200
    assert client.get("/settings").status_code == 200
    assert client.get("/phones").status_code == 200


def test_contacts_optimistic_lock_soft_delete_and_empty_guard(app):
    client = app.test_client()
    login(client)
    post(client, "/contacts/add", revision=0, name="Alice", office="123")
    store = app.extensions["store"]
    contact = store.contacts()[0]
    post(client, "/contacts/edit", revision=0, id=contact["id"], name="Stale", office="999")
    assert store.contacts()[0]["name"] == "Alice"
    post(client, "/contacts/delete", revision=1, id=contact["id"])
    assert len(store.contacts()) == 1
    post(client, "/contacts/delete", revision=1, id=contact["id"], confirm_empty="yes")
    assert store.contacts() == []
    assert store.contacts(True)[0]["name"] == "Alice"
    post(client, "/contacts/restore", revision=2, id=contact["id"])
    assert store.contacts()[0]["name"] == "Alice"
    assert store.get("revision") == 3


def test_xml_csv_import_export_and_secrets(app):
    client = app.test_client()
    login(client)
    with client.session_transaction() as session:
        token = session["csrf"]
    content = xml_for([dict(name="<Alice & Bob>", office="+61 123", mobile="", other="")])
    response = client.post(
        "/import",
        data={"csrf": token, "revision": "0", "file": (io.BytesIO(content), "contacts.xml")},
    )
    assert response.status_code == 302
    assert parse_xml(client.get("/export.xml").data)[0]["name"] == "<Alice & Bob>"
    csv_content = client.get("/export.csv").data
    assert b"'+61 123" in csv_content
    client.post(
        "/import",
        data={"csrf": token, "revision": "1", "file": (io.BytesIO(csv_content), "contacts.csv")},
    )
    store = app.extensions["store"]
    assert store.contacts()[0]["office"] == "+61 123"
    post(
        client,
        "/settings",
        subnets="192.168.10.0/24",
        username="admin",
        phone_password="secret-phone-password",
    )
    assert store.password() == "secret-phone-password"
    assert "secret-phone-password" not in store.get("phone_password")
    assert b"secret-phone-password" not in client.get("/settings").data


def test_malicious_xml_and_invalid_networks():
    with pytest.raises(DefusedXmlException):
        parse_xml(
            b'<!DOCTYPE x [<!ENTITY p SYSTEM "file:///etc/passwd">]><vp_contact>&p;</vp_contact>'
        )
    for text in ("0.0.0.0/0", "127.0.0.1/32", "8.8.8.0/24", "192.168.0.0/16", "169.254.0.0/24"):
        with pytest.raises(ValueError):
            subnets_from(text)
    assert subnets_from("192.168.10.54/24") == ["192.168.10.0/24"]
    with pytest.raises(ValueError):
        validate(dict(name="Alice", office="=HYPERLINK()"))


class FakePhone:
    def __init__(self, ip, fingerprint=None, timeout=None):
        self.content = xml_for([dict(name="Existing", office="100", mobile="", other="")])
        self.imported = False
        self.closed = False

    def login(self, username, password):
        return {"mac": "249ad8a2b726", "firmware": "test"}

    def export(self):
        return self.content

    def import_xml(self, content):
        self.imported = True
        self.content = content

    def logout(self):
        self.closed = True


def enrolled(store):
    store.put("phone_password", store.cipher.encrypt(b"password").decode())
    store.change("add", ("Alice", "200", "", ""), 0)
    with store.db() as db:
        db.execute(
            "INSERT INTO phones(fingerprint,ip,model,mac,enrolled,seen) VALUES (?,?,?,?,1,?)",
            ("abc", "192.168.10.54", "T43U", "249ad8a2b726", time.time()),
        )
    return store.phones()[0]


def test_sync_backup_then_import_and_verify(store):
    row = enrolled(store)
    phone = FakePhone(row["ip"])

    def import_and_check_backup(content):
        backups = list((store.folder / "phone-backups").rglob("*.xml"))
        assert len(backups) == 1
        assert parse_xml(backups[0].read_bytes())[0]["name"] == "Existing"
        phone.content = content
        phone.imported = True

    phone.import_xml = import_and_check_backup
    sync_phone(store, row, lambda *args: phone)
    updated = store.phones()[0]
    assert updated["status"] == "Up to date" and updated["revision"] == 1
    assert phone.imported and phone.closed
    assert canonical(parse_xml(phone.content)) == canonical(store.contacts())


def test_verification_failure_halts_further_updates(store):
    row = enrolled(store)
    phone = FakePhone(row["ip"])
    phone.import_xml = lambda content: None
    sync_phone(store, row, lambda *args: phone)
    assert store.phones()[0]["halted"] == 1
    assert store.phones()[0]["revision"] == -1
    assert "Verification failed" in store.phones()[0]["error"]


@pytest.mark.parametrize(
    "failure,halted", [(BusyPhone("busy"), 0), (TimeoutError(), 1), (UnsafePhone("changed"), 1)]
)
def test_ambiguous_upload_and_busy_phone(store, failure, halted):
    row = enrolled(store)
    phone = FakePhone(row["ip"])

    def fail(content):
        raise failure

    phone.import_xml = fail
    sync_phone(store, row, lambda *args: phone)
    assert store.phones()[0]["halted"] == halted
    assert phone.closed


def test_wrong_identity_never_imports(store):
    row = enrolled(store)
    phone = FakePhone(row["ip"])
    phone.login = lambda *args: {"mac": "000000000000", "firmware": "test"}
    sync_phone(store, row, lambda *args: phone)
    assert not phone.imported
    assert store.phones()[0]["halted"]


def test_discovery_follows_dhcp_without_enrolling_new_phones(store):
    store.put("subnets", ["192.168.10.54/32"])

    class Discovery:
        def __init__(self, ip, timeout):
            pass

        def identify(self):
            return {"ip": "192.168.10.54", "model": "T43U", "fingerprint": "same"}

    discover(store, Discovery)
    assert store.phones()[0]["enrolled"] == 0
    with store.db() as db:
        db.execute("UPDATE phones SET ip='192.168.10.99',enrolled=1,mac='249ad8a2b726'")
    discover(store, Discovery)
    assert len(store.phones()) == 1
    assert store.phones()[0]["ip"] == "192.168.10.54"
    assert store.phones()[0]["enrolled"] == 1


def test_database_persists_and_daily_backup_is_consistent(store):
    store.change("add", ("Alice", "100", "", ""), 0)
    store.backup_database()
    reopened = Store(store.folder)
    assert reopened.contacts()[0]["name"] == "Alice"
    import sqlite3

    with sqlite3.connect(next((store.folder / "database-backups").glob("*.sqlite3"))) as db:
        assert db.execute("SELECT name FROM contacts").fetchone()[0] == "Alice"


def test_empty_uninitialized_directory_never_writes(store):
    phone = FakePhone("192.168.10.54")
    sync_phone(store, {"ip": "192.168.10.54"}, lambda *args: phone)
    assert not phone.imported


def test_empty_initialized_directory_propagates(store):
    row = enrolled(store)
    store.change("delete", (store.contacts()[0]["id"],), 1)
    phone = FakePhone(row["ip"])
    sync_phone(store, row, lambda *args: phone)
    assert phone.imported
    assert parse_xml(phone.content) == []


def test_snapshot_revision_remains_pending_if_contact_changes_during_upload(store):
    row = enrolled(store)
    phone = FakePhone(row["ip"])

    def upload_and_edit(content):
        phone.content = content
        store.change("add", ("Bob", "300", "", ""), 1)

    phone.import_xml = upload_and_edit
    sync_phone(store, row, lambda *args: phone)
    assert store.phones()[0]["revision"] == 1
    assert store.get("revision") == 2


def test_health_checks_worker_and_headers(app):
    client = app.test_client()
    assert client.get("/health").status_code == 503
    app.extensions["store"].put("heartbeat", time.time())
    assert client.get("/health").status_code == 200
    response = client.get("/login")
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


def test_no_secret_in_config_export(app):
    client = app.test_client()
    login(client)
    assert "password" not in json.dumps(client.get("/status").json)
