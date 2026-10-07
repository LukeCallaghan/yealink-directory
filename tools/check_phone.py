"""Read-only integration check against an explicitly supplied LAN phone."""

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from directory.phonebook import parse_xml
from directory.phones import Phone

parser = argparse.ArgumentParser()
parser.add_argument("ip")
parser.add_argument("--fingerprint", required=True)
args = parser.parse_args()
phone = Phone(args.ip, args.fingerprint)
try:
    identity = phone.login("admin", getpass.getpass("Phone administrator password: "))
    contacts = parse_xml(phone.export())
    print("Authenticated identity:", identity)
    print("Read-only export verified:", len(contacts), "contacts")
finally:
    phone.logout()
