import base64
import urllib.parse

import pytest
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from defusedxml.common import DefusedXmlException

from directory.legacy import LegacyPhone, result_info
from directory.phonebook import canonical, parse_xml, xml_for
from directory.phones import BusyPhone, Phone, PhoneError, UnsafePhone

FRAGMENT = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b'<root_group><group display_name="All Contacts"/></root_group>\n'
    b'<root_contact><contact display_name="Alice" office_number="123"/></root_contact>'
)


def test_older_xml_fragment_roundtrip_and_rejects_extra_roots():
    contacts = parse_xml(FRAGMENT)
    assert canonical(parse_xml(xml_for(contacts))) == canonical(contacts)
    with pytest.raises(ValueError):
        parse_xml(FRAGMENT + b"<unexpected/>")
    with pytest.raises(DefusedXmlException):
        parse_xml(b'<!DOCTYPE vp_contact [<!ENTITY x "secret">]><vp_contact>&x;</vp_contact>')


def test_legacy_login_export_import_protocol():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_numbers()
    variables = (
        f'var g_rsa_n="{public.n:x}"; var g_rsa_e="{public.e:x}"; '
        'var g_strToken="csrf-token"; var g_strFirmware="66.86.25.6";'
    ).encode()
    calls = []

    class FakePhone:
        cookies = [type("Cookie", (), {"name": "JSESSIONID", "value": "testsession"})()]
        token = ""
        busy = False
        import_result = 0

        def request(self, path, body=None, content_type="application/json"):
            calls.append(path)
            params = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            if params.get("q") == ["loginForm"]:
                return variables
            if params.get("q") == ["login"]:
                fields = urllib.parse.parse_qs(body.decode())
                key = bytes.fromhex(
                    private.decrypt(bytes.fromhex(fields["rsakey"][0]), padding.PKCS1v15()).decode()
                )
                iv = bytes.fromhex(
                    private.decrypt(bytes.fromhex(fields["rsaiv"][0]), padding.PKCS1v15()).decode()
                )
                decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
                plain = decryptor.update(base64.b64decode(fields["pwd"][0])) + decryptor.finalize()
                assert plain.rstrip(b"\x00").split(b";")[1:] == [b"testsession", b"password"]
                assert fields["username"] == ["admin"]
                return b'<html><div id="_RES_INFO_">{"authstatus":"done"}</div></html>'
            if params.get("p") == ["status"]:
                return variables + b'<label dvalue="80:5E:C0:00:00:01" id="tdMACAddress"></label>'
            if params.get("p") == ["download"]:
                assert body is None
                return FRAGMENT
            if params.get("p") == ["talking"]:
                value = b"1" if self.busy else b"0"
                return b'<div id="_RES_INFO_">{"talking":"' + value + b'"}</div>'
            if params.get("p") == ["contactsbasic"]:
                return variables
            if params.get("p") == ["upload"]:
                assert params["token"] == ["csrf-token"]
                assert private.decrypt(
                    bytes.fromhex(params["maxlength"][0]), padding.PKCS1v15()
                ) == (b"testsession;2MB")
                assert b'name="UploadName"; filename="contact.xml"' in body
                assert b"<vp_contact" not in body
                xml = body.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
                assert canonical(parse_xml(xml)) == canonical(parse_xml(FRAGMENT))
                return f'<div id="_RES_INFO_">{{"result":{self.import_result}}}</div>'.encode()
            assert params.get("q") == ["logout"]
            return b""

    phone = FakePhone()
    adapter = LegacyPhone(phone)
    assert adapter.login("admin", "password") == {"mac": "805ec0000001", "firmware": "66.86.25.6"}
    assert adapter.export() == FRAGMENT
    adapter.import_xml(xml_for(parse_xml(FRAGMENT)))
    phone.busy = True
    uploads = len([p for p in calls if "p=upload" in p])
    with pytest.raises(BusyPhone):
        adapter.import_xml(FRAGMENT)
    assert len([p for p in calls if "p=upload" in p]) == uploads
    phone.busy = False
    phone.import_result = 5
    with pytest.raises(UnsafePhone, match="rejected"):
        adapter.import_xml(FRAGMENT)
    adapter.logout()


@pytest.mark.parametrize("status", ["none", "error", "lock"])
def test_legacy_auth_errors_are_actionable(status):
    with pytest.raises(UnsafePhone, match="login failed"):
        result_info(f'<div id="_RES_INFO_">{{"authstatus":"{status}"}}</div>'.encode())


def test_non_json_modern_response_has_useful_error():
    with pytest.raises(PhoneError, match="non-JSON.*firmware"):
        Phone.json_response("/api/common/info", b"<html>older interface</html>")


def test_phone_selects_legacy_interface_from_login_page(monkeypatch):
    phone = Phone("192.168.1.135")
    phone.observed.append("pin")
    monkeypatch.setattr(
        phone,
        "request",
        lambda *a, **k: (
            b'<title>Yealink T46S Phone</title><script src="/js/pages/page_login.js"></script>'
            b'var g_rsa_n="abc";'
        ),
    )
    monkeypatch.setattr(LegacyPhone, "login", lambda *a: {"mac": "test", "firmware": "test"})
    assert phone.login("admin", "password")["mac"] == "test"
    assert isinstance(phone.legacy, LegacyPhone)
