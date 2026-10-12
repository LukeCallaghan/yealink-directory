import hashlib
import http.client
import json
import urllib.parse

import pytest
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from directory.phonebook import parse_xml, xml_for
from directory.phones import DiscoveryRedirect, NoRedirect, Phone, PinnedConnection, UnsafePhone


def test_pin_rejects_changed_certificate_before_sending_requests(monkeypatch):
    class Socket:
        closed = False

        def getpeercert(self, binary_form):
            return b"changed certificate"

        def close(self):
            self.closed = True

    socket = Socket()
    monkeypatch.setattr(
        http.client.HTTPSConnection,
        "connect",
        lambda connection: setattr(connection, "sock", socket),
    )
    connection = PinnedConnection("192.168.10.54", fingerprint="wrong", observed=[])
    with pytest.raises(UnsafePhone, match="certificate changed"):
        connection.connect()
    assert socket.closed


def test_authenticated_api_protocol_and_rsa_encryption():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_numbers()
    content = xml_for([{"name": "Alice", "office": "123", "mobile": "", "other": ""}])
    calls = []

    class Response:
        def __init__(self, content):
            self.content = content

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            return self.content

    class Opener:
        def open(self, req, timeout):
            calls.append(req)
            path = urllib.parse.urlsplit(req.full_url).path
            if path == "/":
                return Response(b"<title>Yealink T43U Phone</title>")
            if path == "/api/common/info" and "p=Login" in req.full_url:
                return Response(
                    json.dumps(
                        {
                            "ret": "failed",
                            "data": False,
                            "error": {"rsaN": format(public.n, "x"), "rsaE": format(public.e, "x")},
                        }
                    ).encode()
                )
            if path == "/api/auth/login":
                data = urllib.parse.parse_qs(req.data.decode())
                assert data["username"] == ["admin"]
                encrypted = bytes.fromhex(data["pwd"][0].removeprefix("__WUI_ENC__:"))
                assert key.decrypt(encrypted, padding.PKCS1v15()) == b"test-password"
                return Response(b'{"ret":"ok","data":{}}')
            if path == "/api/common/info":
                return Response(
                    b'{"ret":"ok","data":{"wui.device.mac":"24:9A:D8:A2:B7:26",'
                    b'"wui.device.firmware":"test","wui.common.token":"csrf-token"}}'
                )
            if path == "/api/common/info/status/talking":
                return Response(b'{"ret":"ok","data":false}')
            assert req.get_header("X-csrftoken") == "csrf-token"
            if path == "/api/contacts/file":
                assert urllib.parse.parse_qs(req.data.decode())["csrfmiddlewaretoken"] == [
                    "csrf-token"
                ]
                return Response(content)
            if path == "/api/contacts/uploadxml":
                assert req.get_method() == "POST"
                assert urllib.parse.parse_qs(urllib.parse.urlsplit(req.full_url).query) == {
                    "overwite": ["true"]
                }
                assert b'name="file"; filename="contact.xml"' in req.data
                assert content in req.data
                return Response(b'{"ret":"ok","data":{}}')
            if path == "/api/auth/logout":
                return Response(b'{"ret":"ok","data":{}}')
            raise AssertionError(path)

    phone = Phone("192.168.10.54", "pin")
    phone.observed.append("pin")
    phone.opener = Opener()
    phone.discovery_opener = phone.opener
    assert phone.login("admin", "test-password")["mac"] == "249ad8a2b726"
    assert parse_xml(phone.export())[0]["name"] == "Alice"
    phone.import_xml(content)
    phone.logout()
    assert len(calls) == 8


def test_redirects_never_forward_session_or_credentials():
    with pytest.raises(UnsafePhone):
        NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.com")


def test_discovery_redirect_accepts_same_origin_without_forwarding_headers():
    request = urllib.request.Request(
        "https://192.168.10.54/",
        headers={"Cookie": "session=secret", "Authorization": "secret", "X-CSRFToken": "secret"},
    )
    redirected = DiscoveryRedirect().redirect_request(
        request, None, 302, "", {}, "https://192.168.10.54:443/servlet?p=login"
    )
    assert redirected.full_url == "https://192.168.10.54:443/servlet?p=login"
    assert redirected.get_method() == "GET"
    assert redirected.data is None
    assert redirected.header_items() == []


@pytest.mark.parametrize(
    "target",
    [
        "http://192.168.10.54/",
        "https://192.168.10.55/",
        "https://example.com/",
        "https://192.168.10.54:8443/",
        "https://admin:secret@192.168.10.54/",
    ],
)
def test_discovery_redirect_rejects_other_origins(target):
    request = urllib.request.Request("https://192.168.10.54/")
    with pytest.raises(UnsafePhone, match="outside"):
        DiscoveryRedirect().redirect_request(request, None, 302, "", {}, target)


def test_discovery_redirect_rejects_post():
    request = urllib.request.Request("https://192.168.10.54/", data=b"password=secret")
    with pytest.raises(UnsafePhone, match="outside"):
        DiscoveryRedirect().redirect_request(
            request, None, 302, "", {}, "https://192.168.10.54/login"
        )


def test_identify_uses_anonymous_opener_without_session_token():
    phone = Phone("192.168.10.54")
    phone.token = "saved-session-token"
    phone.observed.append("certificate")

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            return b"<title>Yealink T46S Phone</title>"

    class Opener:
        def open(self, request, timeout):
            assert request.get_method() == "GET"
            assert request.get_header("X-csrftoken") is None
            assert request.get_header("Cookie") is None
            return Response()

    phone.discovery_opener = Opener()
    assert phone.identify()["model"] == "T46S"


def test_pin_accepts_matching_certificate(monkeypatch):
    class Socket:
        def getpeercert(self, binary_form):
            return b"original certificate"

    monkeypatch.setattr(
        http.client.HTTPSConnection,
        "connect",
        lambda connection: setattr(connection, "sock", Socket()),
    )
    pin = hashlib.sha256(b"original certificate").hexdigest()
    observed = []
    PinnedConnection("192.168.10.54", fingerprint=pin, observed=observed).connect()
    assert observed == [pin]
