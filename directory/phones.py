import hashlib
import http.client
import http.cookiejar
import ipaddress
import json
import re
import secrets
import ssl
import urllib.parse
import urllib.request

from .phonebook import parse_xml


class PhoneError(Exception):
    pass


class UnsafePhone(PhoneError):
    """Requires operator review before further writes."""


class BusyPhone(PhoneError):
    pass


def private_address(address):
    return any(
        address in ipaddress.IPv4Network(network)
        for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    )


class PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, *args, fingerprint=None, observed=None, **kwargs):
        self.fingerprint = fingerprint
        self.observed = observed
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        kwargs["context"] = context
        super().__init__(*args, **kwargs)

    def connect(self):
        super().connect()
        actual = hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()
        if self.fingerprint and not secrets.compare_digest(self.fingerprint, actual):
            self.close()
            raise UnsafePhone(
                "Phone certificate changed. Review its identity before trusting it again."
            )
        self.observed.append(actual)


class PinnedHandler(urllib.request.HTTPSHandler):
    def __init__(self, fingerprint, observed):
        super().__init__()
        self.fingerprint, self.observed = fingerprint, observed

    def https_open(self, request):
        def connection(*args, **kwargs):
            return PinnedConnection(
                *args, fingerprint=self.fingerprint, observed=self.observed, **kwargs
            )

        return self.do_open(connection, request)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise UnsafePhone("Phone redirected the request. Refusing to forward credentials.")


def rsa_password(password, modulus, exponent):
    n, e = int(modulus, 16), int(exponent, 16)
    size = (n.bit_length() + 7) // 8
    message = password.encode()
    length = size - len(message) - 3
    if length < 8 or size < 128:
        raise UnsafePhone("Unsupported RSA key or password length.")
    padding = bytes(secrets.randbelow(255) + 1 for _ in range(length))
    value = int.from_bytes(b"\x00\x02" + padding + b"\x00" + message, "big")
    return "__WUI_ENC__:" + pow(value, e, n).to_bytes(size, "big").hex()


def field(info, *names):
    for name in names:
        if name in info:
            return info[name]
        for key, value in info.items():
            if key.split(".")[-1].lower() == name.lower():
                return value
    return ""


class Phone:
    def __init__(self, ip, fingerprint=None, timeout=8):
        address = ipaddress.IPv4Address(ip)
        if not private_address(address):
            raise UnsafePhone("Only private LAN addresses are supported.")
        self.ip = str(address)
        self.base = f"https://{address}"
        self.observed = []
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            PinnedHandler(fingerprint, self.observed),
            urllib.request.HTTPCookieProcessor(self.cookies),
        )
        self.token = ""
        self.timeout = timeout

    def request(self, path, body=None, content_type="application/json"):
        headers = {"Content-Type": content_type, "Referer": self.base + "/"}
        if self.token:
            headers["X-CSRFToken"] = self.token
        req = urllib.request.Request(self.base + path, body, headers)
        with self.opener.open(req, timeout=self.timeout) as response:
            content = response.read(2_000_001)
        if len(content) > 2_000_000:
            raise UnsafePhone("Phone response exceeded the size limit.")
        return content

    def post(self, path, payload, preauth=False):
        result = json.loads(self.request(path, json.dumps(payload).encode()))
        if result.get("ret") not in ("ok", "true", True):
            if preauth and isinstance(result.get("error"), dict):
                return result["error"]
            raise PhoneError(
                "Phone rejected the request; check administrator credentials and firmware."
            )
        return result.get("data", {})

    def identify(self):
        page = self.request("/").decode(errors="replace")
        match = re.search(r"<title>Yealink (T46S|T43U) Phone</title>", page, re.I)
        if not match:
            raise PhoneError("Not a supported Yealink phone.")
        return {"ip": self.ip, "model": match.group(1).upper(), "fingerprint": self.observed[0]}

    def login(self, username, password):
        # Check identity on the pinned connection before transmitting credentials.
        self.identify()
        key = self.post(
            "/api/common/info?p=Login",
            {"idlist": ["wui.common.rsaN", "wui.common.rsaE"]},
            preauth=True,
        )
        encrypted = rsa_password(password, field(key, "rsaN"), field(key, "rsaE"))
        body = urllib.parse.urlencode({"username": username, "pwd": encrypted}).encode()
        result = json.loads(
            self.request("/api/auth/login?p=Login", body, "application/x-www-form-urlencoded")
        )
        if result.get("ret") != "ok":
            raise UnsafePhone("Administrator login failed. Check credentials before retrying.")
        info = self.post("/api/common/info?p=ContactsLocal", {"idlist": ["wui"]})
        self.token = field(info, "token") or next(
            (c.value for c in self.cookies if c.name == "csrftoken"), ""
        )
        mac = re.sub(r"[^0-9a-f]", "", str(field(info, "mac", "macAddress")).lower())
        if len(mac) != 12 or not self.token:
            raise UnsafePhone("Firmware did not supply a MAC address and CSRF token.")
        return {"mac": mac, "firmware": str(field(info, "firmware"))}

    def logout(self):
        try:
            self.post("/api/auth/logout?p=ContactsLocal", {})
        except Exception:
            pass

    def export(self):
        body = urllib.parse.urlencode({"csrfmiddlewaretoken": self.token}).encode()
        content = self.request(
            "/api/contacts/file?type=xml", body, "application/x-www-form-urlencoded"
        )
        parse_xml(content)
        return content

    def import_xml(self, payload):
        status = json.loads(self.request("/api/common/info/status/talking"))
        if status.get("ret") != "ok" or status.get("data") is not False:
            raise BusyPhone("Phone is busy; waiting until it is idle.")
        boundary = "----YealinkDirectory" + secrets.token_hex(12)
        body = (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            'filename="contact.xml"\r\nContent-Type: application/xml\r\n\r\n'
        ).encode()
        body += payload + f"\r\n--{boundary}--\r\n".encode()
        result = json.loads(
            self.request(
                "/api/contacts/uploadxml?overwite=true",
                body,
                f"multipart/form-data; boundary={boundary}",
            )
        )
        if result.get("ret") != "ok":
            raise UnsafePhone(
                "Phone rejected the directory import; review its firmware before retrying."
            )


def subnets_from(text):
    networks = []
    for part in text.replace(",", "\n").splitlines():
        if not part.strip():
            continue
        net = ipaddress.IPv4Network(part.strip(), strict=False)
        if (
            not private_address(net.network_address)
            or not private_address(net.broadcast_address)
            or net.prefixlen < 24
        ):
            raise ValueError("Use private IPv4 subnets of /24 or smaller, one per line.")
        networks.append(str(net))
    if sum(ipaddress.IPv4Network(n).num_addresses for n in networks) > 1024:
        raise ValueError("Scan at most 1,024 addresses across all subnets.")
    return sorted(set(networks))
