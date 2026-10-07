import ipaddress
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor

from .phonebook import canonical, parse_xml, xml_for
from .phones import BusyPhone, Phone, UnsafePhone
from .store import Store

log = logging.getLogger(__name__)


def discover(store, factory=Phone):
    addresses = sorted(
        {
            str(ip)
            for network in store.get("subnets", [])
            for ip in ipaddress.IPv4Network(network).hosts()
        }
    )

    def probe(ip):
        try:
            return factory(ip, timeout=2).identify()
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=16) as pool:
        for result in pool.map(probe, addresses):
            store.put("heartbeat", time.time())
            if result:
                with store.db() as db:
                    db.execute(
                        """INSERT INTO phones(fingerprint,ip,model,seen)
                        VALUES (?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET
                        ip=excluded.ip,model=excluded.model,seen=excluded.seen""",
                        (result["fingerprint"], result["ip"], result["model"], time.time()),
                    )
    store.put("last_scan", time.time())
    store.put("scan_requested", False)


def sync_phone(store, row, factory=Phone):
    if not store.get("initialized") or not store.password():
        return
    phone = factory(row["ip"], row["fingerprint"])
    wrote = False
    try:
        identity = phone.login(store.get("username"), store.password())
        if identity["mac"] != row["mac"]:
            raise UnsafePhone("MAC address differs from the enrolled phone. No directory was sent.")
        revision, contacts = store.snapshot()
        before = phone.export()
        if canonical(parse_xml(before)) != canonical(contacts):
            folder = store.folder / "phone-backups" / row["mac"]
            folder.mkdir(parents=True, exist_ok=True)
            backup = folder / f"{time.time_ns()}-before-r{revision}.xml"
            # Backup must be durably stored before touching the device.
            with backup.open("xb") as file:
                file.write(before)
                file.flush()
                os.fsync(file.fileno())
            store.event(
                row["id"],
                "Directory backed up before replacement",
                str(backup.relative_to(store.folder)),
            )
            # From here even a network timeout can mean that the phone changed.
            # Stop retries on an ambiguous outcome until an operator reviews it.
            wrote = True
            phone.import_xml(xml_for(contacts))
            after = phone.export()
            if canonical(parse_xml(after)) != canonical(contacts):
                folder.joinpath(f"{time.time_ns()}-verification-failed.xml").write_bytes(after)
                raise UnsafePhone(
                    "Verification failed. Updates paused; original directory backup retained."
                )
            store.event(row["id"], f"Directory revision {revision} imported and verified")
        with store.db() as db:
            db.execute(
                "UPDATE phones SET revision=?,checked=?,status='Up to date',error='',"
                "retry_at=0,firmware=? WHERE id=?",
                (revision, time.time(), identity["firmware"], row["id"]),
            )
    except Exception as error:
        halted = isinstance(error, UnsafePhone) or (wrote and not isinstance(error, BusyPhone))
        message = (
            str(error)
            if isinstance(error, (UnsafePhone, BusyPhone))
            else ("Connection or authentication failed. Check reachability and credentials.")
        )
        with store.db() as db:
            db.execute(
                "UPDATE phones SET status=?,error=?,halted=?,retry_at=? WHERE id=?",
                (
                    "Needs attention" if halted else "Waiting to retry",
                    message,
                    int(halted),
                    time.time() + 120,
                    row["id"],
                ),
            )
        store.event(row["id"], message)
    finally:
        phone.logout()


def run(folder):
    logging.basicConfig(level=logging.INFO)
    store = Store(folder)
    next_backup = 0
    while True:
        try:
            store.put("heartbeat", time.time())
            if time.time() >= next_backup:
                store.backup_database()
                next_backup = time.time() + 86400
            if store.get("scan_requested") or time.time() - store.get("last_scan", 0) > 300:
                discover(store)
            revision = store.get("revision")
            for row in store.phones():
                if (
                    row["enrolled"]
                    and not row["halted"]
                    and row["retry_at"] <= time.time()
                    and (row["revision"] != revision or time.time() - row["checked"] > 900)
                ):
                    store.put("heartbeat", time.time())
                    sync_phone(store, row)
        except Exception:
            log.exception("Background cycle failed")
        time.sleep(3)
