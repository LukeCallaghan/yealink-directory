"""Servlet web interface verified on T46S firmware 66.86.25.6."""

import base64
import html
import json
import re
import secrets
import urllib.parse
import xml.etree.ElementTree as ET
from html.parser import HTMLParser

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from defusedxml.ElementTree import fromstring

from .phonebook import parse_xml
from .phones import BusyPhone, PhoneError, UnsafePhone, rsa_password


def variable(page, name):
    match = re.search(r"\bvar\s+" + re.escape(name) + r'\s*=\s*["\x27]([^"\x27]*)["\x27]', page)
    if not match:
        raise UnsafePhone(f"Older phone interface did not supply {name}.")
    return match.group(1)


def result_info(content):
    page = content.decode(errors="replace")
    match = re.search(r'<div\b[^>]*\bid=["\x27]_RES_INFO_["\x27][^>]*>(.*?)</div>', page, re.S)
    try:
        result = json.loads(html.unescape(match.group(1)) if match else page)
    except ValueError as error:
        raise PhoneError("Older phone interface returned an unsupported response.") from error
    if not isinstance(result, dict):
        raise PhoneError("Older phone interface returned an unsupported response.")
    if result.get("authstatus") in ("none", "error", "lock"):
        raise UnsafePhone("Administrator login failed or expired. Check credentials.")
    return result


class StatusParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.mac = ""

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id") == "tdMACAddress":
            self.mac = values.get("dvalue", "")


class LegacyPhone:
    def __init__(self, phone):
        self.phone = phone
        self.modulus = self.exponent = ""

    def session(self):
        value = next((c.value for c in self.phone.cookies if c.name == "JSESSIONID"), "")
        if not re.fullmatch(r"\w+", value):
            raise UnsafePhone("Older phone interface did not supply a valid session cookie.")
        return value

    def rsa(self, text):
        return rsa_password(text, self.modulus, self.exponent).removeprefix("__WUI_ENC__:")

    def login(self, username, password):
        page = self.phone.request("/servlet?m=mod_listener&p=login&q=loginForm").decode()
        self.modulus, self.exponent = variable(page, "g_rsa_n"), variable(page, "g_rsa_e")
        key, iv = secrets.token_bytes(16), secrets.token_bytes(16)
        # Match YLForm.Encrypt: random prefix; session; password, AES-CBC with zero padding.
        plain = f"{secrets.randbelow(1_000_000)};{self.session()};{password}".encode()
        plain += b"\x00" * ((-len(plain)) % 16)
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        encrypted = base64.b64encode(encryptor.update(plain) + encryptor.finalize()).decode()
        body = urllib.parse.urlencode(
            {
                "username": username,
                "pwd": encrypted,
                "rsakey": self.rsa(key.hex()),
                "rsaiv": self.rsa(iv.hex()),
            }
        ).encode()
        result = result_info(
            self.phone.request(
                "/servlet?m=mod_listener&p=login&q=login", body, "application/x-www-form-urlencoded"
            )
        )
        if result.get("authstatus") != "done":
            raise UnsafePhone("Administrator login failed. Check credentials before retrying.")
        page = self.phone.request("/servlet?m=mod_data&p=status&q=load").decode()
        parser = StatusParser()
        parser.feed(page)
        mac = re.sub(r"[^0-9a-f]", "", parser.mac.lower())
        self.phone.token = variable(page, "g_strToken")
        if len(mac) != 12 or not self.phone.token:
            raise UnsafePhone("Older phone interface did not supply a MAC address and CSRF token.")
        return {"mac": mac, "firmware": variable(page, "g_strFirmware")}

    def export(self):
        # GET is supported by this read-only endpoint; an empty POST is rejected on
        # firmware 66.86.25.6 even though its JavaScript builds a POST download form.
        content = self.phone.request("/servlet?m=mod_res&p=download&type=downloadxml")
        parse_xml(content)
        return content

    def import_xml(self, payload):
        parse_xml(payload)
        status = result_info(self.phone.request("/servlet?m=mod_webd&p=talking"))
        if status.get("talking") not in ("0", 0):
            raise BusyPhone("Phone is busy; waiting until it is idle.")
        page = self.phone.request("/servlet?m=mod_data&p=contactsbasic&q=load").decode()
        self.modulus, self.exponent = variable(page, "g_rsa_n"), variable(page, "g_rsa_e")
        self.phone.token = variable(page, "g_strToken")
        # Use the older firmware's sibling-element format, preserving already exported XML.
        fragment = re.sub(rb"^\s*<\?xml[^?]*\?>", b"", payload).lstrip()
        if not fragment.startswith(b"<root_group"):
            root = fromstring(payload)
            payload = b'<?xml version="1.0" encoding="utf-8"?>\n' + b"\n".join(
                ET.tostring(child, encoding="utf-8") for child in root
            )
        params = urllib.parse.urlencode(
            {
                "m": "mod_res",
                "p": "upload",
                "type": "contactxml",
                "maxlength": self.rsa(self.session() + ";2MB"),
                "token": self.phone.token,
            }
        )
        boundary = "----YealinkDirectory" + secrets.token_hex(12)
        body = (
            (
                f'--{boundary}\r\nContent-Disposition: form-data; name="UploadName"; '
                'filename="contact.xml"\r\nContent-Type: application/xml\r\n\r\n'
            ).encode()
            + payload
            + f"\r\n--{boundary}--\r\n".encode()
        )
        result = result_info(
            self.phone.request(
                "/servlet?" + params, body, f"multipart/form-data; boundary={boundary}"
            )
        )
        if str(result.get("result")) not in ("0", "46"):
            raise UnsafePhone("Phone rejected the directory import; original backup retained.")

    def logout(self):
        self.phone.request("/servlet?m=mod_listener&p=login&q=logout")
