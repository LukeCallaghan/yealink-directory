# Deployment

Publish versioned images to a private GitHub Container Registry (GHCR) package,
then pull and run them on the mini PC. Internet access is required to install
Docker and download images. The app operates without internet access afterward.

## Mini PC requirements

Use Ubuntu Server LTS on an Intel/AMD mini PC with Docker Engine and the Docker
Compose plugin installed. Follow the [official Ubuntu installation guide](https://docs.docker.com/engine/install/ubuntu/).
Run the commands below as a user with Docker access; use `sudo docker` if needed,
including for registry login so the same user owns the registry credentials.

- Enable Docker to start at boot: `sudo systemctl enable --now docker`.
- Give the mini PC a stable LAN address or DNS name. Phones can continue using DHCP.
- Allow the mini PC to reach the phones over HTTPS on port 443.
- Allow users on the LAN to reach the app on the chosen port (8081 below).

The existing Compose configuration restarts the app automatically after a reboot.

## Publish a private image

On your development computer, create a GitHub personal access token **classic**
with `write:packages`. The account must have permission to publish the package.
If your organisation requires SSO, authorize the token for that organisation.

From the repository folder, run:

```sh
docker login ghcr.io -u YOUR_GITHUB_USERNAME
docker buildx build --platform linux/amd64 \
  -t ghcr.io/your-account/yealink-directory:0.1.0 \
  --push .
```

Enter the token when Docker prompts for a password. Replace `your-account` with
your lowercase GitHub username or organisation. `linux/amd64` targets Intel/AMD
mini PCs even when building on an Apple Silicon Mac; use `linux/arm64` for an ARM
host instead.

In GitHub, open the package settings and verify that visibility is **Private**
and that the account used by the mini PC has read access. Registry authentication
is separate from the app's shared login password.

See [GitHub's Container Registry documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
for token scopes and package access settings.

## Deploy on the mini PC

Create a permanent deployment folder, for example `~/yealink-directory`. Copy
`compose.yaml` and `.env.example` into it, renaming `.env.example` to `.env`.
The mini PC does not need the source code or `compose.build.yaml`.

Edit `.env`:

```dotenv
APP_PASSWORD=replace-with-a-shared-password-of-at-least-12-characters
IMAGE=ghcr.io/your-account/yealink-directory:0.1.0
PORT=8081
BIND_IP=0.0.0.0
COOKIE_SECURE=0
```

Port 8081 avoids the port 8080 conflict encountered on the development machine.
Choose another available host port if necessary; the container still uses 8080
internally. Keep `COOKIE_SECURE=0` for HTTP. Set it to `1` when serving the app
through a local HTTPS reverse proxy.

Create a separate GitHub personal access token **classic** with `read:packages`
for the mini PC. Its account must have read access to the private package; it
does not need permission to publish images.

```sh
cd ~/yealink-directory
chmod 600 .env
docker login ghcr.io -u YOUR_GITHUB_USERNAME
docker compose pull
docker compose up -d
docker compose ps
```

Enter the read token at the password prompt. Open `http://MINI_PC_IP:8081` and
sign in using `APP_PASSWORD`.

1. In **Settings**, configure the phone subnet(s) and administrator credentials.
2. Import an existing directory or add contacts to establish the shared directory.
3. In **Phones**, review each discovered phone and **Trust and enroll** it.
   Enrollment authorizes replacement of its local directory with the shared one.
4. Check phone status and recent activity to confirm synchronization.

For startup problems, inspect `docker compose logs --tail=100 directory`.

## Update a deployment

Publish each release with a new version tag, such as `0.1.1`. Back up the data
volume before upgrading, then change `IMAGE` in the mini PC's `.env` to the new
tag and run:

```sh
cd ~/yealink-directory
docker compose pull
docker compose up -d
docker compose ps
```

Wait for the container to report healthy and open the app to verify the update.
Pulling downloads the image; `up -d` recreates the container to run it. See
[Docker's Compose update behavior](https://docs.docker.com/reference/cli/docker/compose/up/).

Keep the same deployment folder and Compose project name so updates reuse the
existing named data volume. Contacts, credentials, settings and backups persist
across container recreation. **Do not run `docker compose down -v`**, which
removes the data volume.

To return to a previous release, change `IMAGE` back to its version tag and
repeat the update commands. If a release changes the database schema, rollback
may also require restoring the matching pre-update data backup.

## Back up application data

Stop the service with `docker compose stop directory`, archive the complete
named `directory-data` volume using your Docker backup tooling, then restart it
with `docker compose start directory`. Compose prefixes the volume name with
the project name; `docker volume ls` shows the actual name.

Include the entire volume, especially its encryption key. Daily database
snapshots alone do not contain everything needed for a full restore. Protect
the backup and `.env`, which contain sensitive application data.

## Deploy or update without internet

On a connected computer, pull the published image and save it:

```sh
docker pull --platform linux/amd64 ghcr.io/your-account/yealink-directory:0.1.0
docker image save ghcr.io/your-account/yealink-directory:0.1.0 \
  -o yealink-directory-0.1.0.tar
```

Transfer the archive to the mini PC using removable storage, then run:

```sh
docker image load -i yealink-directory-0.1.0.tar
cd ~/yealink-directory
docker compose up -d --pull never
docker compose ps
```

Set `IMAGE` in `.env` to the transferred image's exact tag before starting. Docker
must already be installed. Repeat this process with a new version for offline
updates; the mini PC does not need registry authentication for loaded images.
