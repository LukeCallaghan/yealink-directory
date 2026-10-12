# Yealink Directory

A small, offline LAN app for maintaining a shared local directory on Yealink
phones. Add, edit, remove, restore, search, and import contacts in a browser.
The background worker discovers DHCP-addressed phones, backs up their contacts,
uploads the directory and verifies a fresh export. No cloud account, CDN,
remote phonebook, or RingCentral configuration change is required.

## Start with Docker

Use a Linux mini PC with Docker Engine and the Compose plugin. Give the mini PC
a stable LAN address or DNS name so users can find the app; phones may continue
using DHCP. The mini PC must be able to reach the phones' HTTPS port 443.

```sh
cp .env.example .env
# Edit .env: choose APP_PASSWORD (12+ characters) and your IMAGE name.
docker compose -f compose.yaml -f compose.build.yaml build
docker compose up -d
```

Open `http://MINI_PC_IP:8080`, sign in, then:

1. In **Settings**, enter the phone subnet(s), administrator username and password.
2. Import an existing Yealink local directory XML export, import CSV, or add contacts.
3. In **Phones**, review each discovered phone and its certificate fingerprint,
   then **Trust and enroll**. This authorizes replacement of that phone's local
   directory with the shared directory. Do not enroll phones with personal
   directories that should remain separate.
4. Check the status and activity log. Phones update after edits, discovery runs
   every five minutes, and enrolled directories are checked for drift every
   fifteen minutes. A busy or unreachable phone waits and retries. Certificate,
   identity, import, and verification errors require review before continuing.

The first startup cannot clear phone contacts: an uninitialized master directory
is never sent. Removing the last contact requires an explicit confirmation.
Removed and replaced app contacts remain available to restore. XML import uses
contact names and office/mobile/other numbers; custom photos, groups, blocklists,
ringtone preferences and line assignments are not part of the shared directory.
Original full XML exports are retained in per-phone backups.

## Image updates

See [DEPLOYMENT.md](DEPLOYMENT.md) for private GitHub Container Registry setup,
mini PC installation, versioned updates, backups, and offline image transfers.

The deployment computer needs only `compose.yaml` and `.env` once an image has
been published. Build and push a versioned image from your development computer:

```sh
docker buildx build --platform linux/amd64 -t YOUR_REGISTRY/yealink-directory:0.1.0 --push .
```

Set `IMAGE=YOUR_REGISTRY/yealink-directory:0.1.0` in the mini PC's `.env`, then:

```sh
docker compose pull
docker compose up -d
```

The named `directory-data` volume survives container recreation and image
updates. It contains SQLite, encrypted phone credentials, the encryption key,
session key, daily database snapshots, and phone backups. **Do not use
`docker compose down -v`** unless intentionally removing all application data.
Versioned tags let you select the previous image if necessary; future database
migrations may require restoring a matching data backup as well.

For a fully disconnected mini PC, transfer the image on removable storage:

```sh
# On a connected build machine, after building/tagging the image:
docker image save YOUR_REGISTRY/yealink-directory:0.1.0 -o yealink-directory.tar
# On the mini PC:
docker image load -i yealink-directory.tar
docker compose up -d --pull never
```

Internet access is needed to download initial build dependencies or pull a new
image. The built image itself requires no internet to run.

If your build network uses a private TLS-inspection CA, provide its trusted PEM
bundle as a temporary build secret (it is not copied into the resulting image):

```sh
docker build --secret id=build_ca,src=/path/to/trusted-ca.pem -t yealink-directory:latest .
```

## Backups and access

Download pre-update XML backups from **Phones → Recent activity** and import
one into the app to restore its contact numbers to the fleet. This intentionally
restores the shared directory rather than original per-phone groups or photos.
For a full data backup, stop the service and archive the entire named volume,
including `key`; restarting the app resumes background work. Daily SQLite
snapshots (last 14) are also kept in `/data/database-backups`, but they do not
replace a full volume backup. Per-phone backups are kept indefinitely.

`APP_PASSWORD` initializes the stored password hash. Changing it in `.env` and
recreating the container changes the password and invalidates existing sessions.
Keep `.env` private. For deployments using Docker secrets, the app also accepts
`APP_PASSWORD_FILE` instead of an environment password (adjust Compose to mount
the secret). Phone credentials are configured in the app and encrypted at rest;
the volume's key can decrypt them, so protect backups of the volume.

The default web listener is HTTP for a trusted LAN. To protect the shared
password on the wire, serve it through your local HTTPS reverse proxy and set
`COOKIE_SECURE=1`. Bind `BIND_IP` to the LAN interface if appropriate. No proxy
headers are trusted by default. Keep the service off the public internet.

Phone HTTPS uses certificate pinning: discovery reads an anonymous page and
records its SHA-256 certificate fingerprint; enrollment explicitly trusts it.
Anonymous discovery follows redirects only to the same phone address and HTTPS
port. It sends no session cookies or authentication tokens. Login and directory
API requests reject redirects.
Every subsequent connection checks that fingerprint before sending credentials.
After DHCP changes, a matching fingerprint finds the phone at its new address,
and its authenticated MAC address is checked before updates. A certificate
change produces a new candidate: pause the old enrollment, review the new phone,
then enroll it. No global TLS bypass is used for enrolled devices.

## Compatibility and limitations

Direct authenticated XML import/export was verified on a RingCentral-connected
T43U with firmware 108.86.25.16. T46S compatibility is **assumed at the user's
request** and has not been tested. The integration uses internal web-interface
endpoints, not a documented public API contract. Unsupported firmware is
reported rather than falling back to provisioning or changing phone settings.
Use a pilot phone before enrolling a fleet. Shared credentials are supported;
per-phone administrator passwords are not currently supported.

Discovery supports private IPv4 subnets of /24 or smaller, at most 1,024
addresses. Larger networks can be split into configured subnets within that
limit. Routed phone VLANs need appropriate network access. Raw sockets,
privileged containers and host networking are unnecessary. Scan only your own
phone networks. If firmware changes a device's certificate or shares identical
certificates across devices, automatic identity tracking needs operator review.

## Development and validation

```sh
uv sync --locked
uv run pytest
uv run ruff check .
APP_PASSWORD='a-long-development-password' DATA_DIR=./data/dev uv run python -m directory
```

The app and worker run in one image as separate supervised processes. If either
exits, the container exits and Docker's restart policy restarts it. The Docker
healthcheck checks both the web service and worker heartbeat. Healthcheck failure
is visible in Docker; Docker does not restart a container solely for being
unhealthy. Contact revision and phone retry state are durable in SQLite.
Dependencies are locked in `uv.lock` and hash-pinned in `requirements.txt`.
The container runs as UID 10001 with a read-only root filesystem and a writable
data volume. Tests use simulated phones and never contact the LAN.

`probe_phone.py` is the earlier standalone test harness; it is excluded from the
image. It is not the production transport.
