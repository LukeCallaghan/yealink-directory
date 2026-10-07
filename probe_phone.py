"""Test the observed T43U web API. Credentials and responses stay out of logs.

This is a test harness, not a production client. --test-self-signed explicitly
accepts the test device's certificate for this run only.
"""
import argparse
import getpass
import http.cookiejar
import json
import secrets
import ssl
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path


def rsa_password(password, modulus, exponent):
    n, e = int(modulus, 16), int(exponent, 16)
    size = (n.bit_length() + 7) // 8
    message = password.encode()
    length = size - len(message) - 3
    if length < 8:
        raise ValueError('Password too long for device RSA key')
    padding = bytes(secrets.randbelow(255) + 1 for _ in range(length))
    value = int.from_bytes(b'\x00\x02' + padding + b'\x00' + message, 'big')
    return '__WUI_ENC__:' + pow(value, e, n).to_bytes(size, 'big').hex()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='192.168.10.54')
    parser.add_argument('--test-self-signed', action='store_true')
    parser.add_argument('--import-backup', type=Path)
    parser.add_argument('--probe-xml-push', action='store_true')
    args = parser.parse_args()
    context = ssl.create_default_context()
    if args.test_self_signed:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(cookies),
    )
    base = f'https://{args.host}'
    token = ''

    def request(path, body=None, content_type='application/json'):
        headers = {'Content-Type': content_type, 'Referer': base + '/'}
        if token:
            headers['X-CSRFToken'] = token
        req = urllib.request.Request(base + path, data=body, headers=headers)
        with opener.open(req, timeout=15) as response:
            return response.read()

    def post(path, payload):
        result = json.loads(request(path, json.dumps(payload).encode()))
        if result.get('ret') not in ('ok', 'true', True) and not path.startswith('/api/common/info'):
            raise RuntimeError(f'{path}: request rejected ({result.get("ret")})')
        return result.get('data', {}) if result.get('ret') in ('ok', 'true', True) else result.get('error', {})

    def update_token(data):
        nonlocal token
        if not isinstance(data, dict):
            data = {}
        token = data.get('token', data.get('wui.common.token', ''))
        if not token:
            token = next((c.value for c in cookies if c.name == 'csrftoken'), '')

    request('/')
    update_token({})
    info = post('/api/common/info?p=Login', {'idlist': ['wui']})
    update_token(info)
    key = post('/api/common/info?p=Login', {'idlist': ['wui.common.rsaN', 'wui.common.rsaE']})
    encrypted = rsa_password(getpass.getpass('Phone administrator password: '),
                             key.get('rsaN', key.get('wui.common.rsaN')),
                             key.get('rsaE', key.get('wui.common.rsaE')))
    login = urllib.parse.urlencode({'username': 'admin', 'pwd': encrypted}).encode()
    result = json.loads(request('/api/auth/login?p=Login', login,
                                'application/x-www-form-urlencoded'))
    if result.get('ret') != 'ok':
        raise RuntimeError('Administrator login rejected')
    info = post('/api/common/info?p=ContactsLocal', {'idlist': ['wui']})
    update_token(info)
    print('Direct API administrator login: successful')
    print('CSRF token present:', bool(token))
    if args.import_backup:
        folder = Path('data/backups')
        folder.mkdir(parents=True, exist_ok=True)

        def export():
            form = urllib.parse.urlencode({'csrfmiddlewaretoken': token}).encode()
            content = request('/api/contacts/file?type=xml', form,
                              'application/x-www-form-urlencoded')
            if ET.fromstring(content).tag != 'vp_contact':
                raise RuntimeError('Export did not return a Yealink contact document')
            return content

        before = export()
        folder.joinpath('t43u-api-before.xml').write_bytes(before)
        payload = args.import_backup.read_bytes()
        # Refuse replacement unless the submitted backup exactly matches the
        # current directory. This harness is intentionally an unchanged test.
        if payload != before:
            raise RuntimeError('Backup differs from current directory; refusing replacement')
        talking = json.loads(request('/api/common/info/status/talking'))
        if talking.get('ret') != 'ok' or talking.get('data') is not False:
            raise RuntimeError('Phone idle state not confirmed; refusing import')
        boundary = '----YealinkTest' + secrets.token_hex(12)
        body = (f'--{boundary}\r\nContent-Disposition: form-data; '
                'name="file"; filename="contact.xml"\r\n'
                'Content-Type: application/xml\r\n\r\n').encode()
        body += payload + f'\r\n--{boundary}--\r\n'.encode()
        result = json.loads(request('/api/contacts/uploadxml?overwite=true', body,
                                    f'multipart/form-data; boundary={boundary}'))
        print('Direct XML import result:', result.get('ret'))
        if result.get('ret') != 'ok':
            raise RuntimeError('Import rejected')
        after = export()
        folder.joinpath('t43u-api-after.xml').write_bytes(after)
        if before != after:
            raise RuntimeError('Post-import export differs; inspect retained backups')
        print('Post-import export matches backup byte for byte')
    if args.probe_xml_push:
        # Empty Execute object performs no phone action; do not configure or
        # enable push access as part of the probe.
        body = b'xml=<YealinkIPPhoneExecute></YealinkIPPhoneExecute>'
        try:
            response = request('/servlet?push=xml', body, 'text/xml')
            Path('data/backups/t43u-xml-push-response.txt').write_bytes(response)
            print('XML push returned:', response[:300].decode(errors='replace'))
        except urllib.error.HTTPError as error:
            print('XML push HTTP status:', error.code)
    post('/api/auth/logout?p=ContactsLocal', {})
    print('Logged out')


if __name__ == '__main__':
    main()
