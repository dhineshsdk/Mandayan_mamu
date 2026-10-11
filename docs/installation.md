# Installing Sutra on a server (on-premises or air-gapped)

The install bundle is one `.tar.gz` that needs **no internet access** on the server: it carries Sutra and every
dependency as wheels, an installer, systemd units, a TLS proxy example and these docs.

## What the server needs

* Linux with systemd (x86-64 or ARM64), 2 CPU cores, 4 GB RAM and disk for your scan exports and evidence files.
* The same Python minor version the bundle was built for. The bundle name says which (`...-py312.tar.gz` is Python
  3.12), and `install.sh` stops with a clear message if it differs. Debian and Ubuntu also need `python3-venv`.
* A TLS reverse proxy in front (nginx example included). Sutra itself listens on `127.0.0.1:8765` only.
* A way to reach your scanners, Jira, directory and similar systems **over your own network**. Nothing else needs to be
  reachable (see [`hardening.md`](hardening.md)).

## 1. Build the bundle (vendor, on a machine with internet)

```
git clone <the Sutra repository> && cd <it>
packaging/build-bundle.sh dist           # same OS, CPU and Python minor version as the target server
```

Output: `dist/sutra-<version>-linux-<arch>-py<NN>.tar.gz` and a `.sha256` file. Set `WITH_CLOUD_AI=1` to also include the
Anthropic SDK if the customer permits the Claude API; leave it off for air-gapped sites.

Before building a release for a customer, put the vendor's licence **public** key in `sutra/data/licence_public.pem`
([`licensing.md`](licensing.md)); the bundle then verifies that customer's keys.

## 2. Install (on the server)

```
sha256sum -c sutra-<...>.tar.gz.sha256       # compare with the file you were sent separately
tar xzf sutra-<...>.tar.gz && cd sutra-<...>
sudo ./install.sh
```

The installer verifies every file in the bundle, creates the unprivileged `sutra` user, a virtualenv in `/opt/sutra`,
`/etc/sutra/sutra.env` (new random secret, `SUTRA_REQUIRE_LICENCE=1`, `SUTRA_EGRESS=allowlist`, AI off, no internet
feeds), the data folder `/var/lib/sutra` (mode 700), the database, and systemd units for the service and a nightly
encrypted backup. It never overwrites an existing `sutra.env` or data, so it is safe to run again.

Options: `--prefix`, `--data`, `--etc`, `--backups`, `--user`, `--python`, `--no-user`, `--no-systemd`. A trial install
needs no root: `./install.sh --prefix ~/s/opt --data ~/s/data --etc ~/s/etc --backups ~/s/bk --no-user --no-systemd`.

## 3. First start

1. Create the first administrator (it prompts for a password of at least 12 characters):
   `cd /var/lib/sutra && set -a && . /etc/sutra/sutra.env && set +a && sudo -E -u sutra /opt/sutra/venv/bin/python -m sutra create-admin --email you@example.in --name "Your Name"`
2. Install TLS in front (`/opt/sutra/nginx.conf.example`) and set `SUTRA_BASE_URL=https://...` in `/etc/sutra/sutra.env`.
3. `systemctl start sutra`, sign in, open **Administration → Modules and licences**, and paste your licence key.
4. Configure single sign-on (`SUTRA_OIDC_*`) and set `SUTRA_ALLOW_LOCAL_LOGIN=0` when it works.
5. Run the check (same environment as step 1): `python -m sutra doctor`. Fix every FAIL; read every WARN.
6. **Copy `/etc/sutra/backup.pass` off the server** and keep it with your other secrets. Backups are encrypted with it
   and cannot be read without it.

## Air-gapped specifics

* **Threat feeds (CISA KEV, FIRST EPSS).** `SUTRA_INTEL_REFRESH=0` by default. Mirror the two feeds inside your network
  and set `SUTRA_KEV_URL` / `SUTRA_EPSS_URL` to the mirror, then `SUTRA_INTEL_REFRESH=1`. Without feeds Sutra uses
  the bundled sample snapshot and says so on the Data screen; exploitation status will be out of date.
* **AI.** Off by default. To use a model inside the network, run an OpenAI-compatible server there and set
  `SUTRA_AI_PROVIDER=local`, `SUTRA_AI_LOCAL_URL`, `SUTRA_AI_LOCAL_MODEL`.
* **Allowed hosts.** Anything outside your private network ranges must be named in `SUTRA_EGRESS_ALLOW`, for example the
  Teams webhook host or `login.microsoftonline.com` for Entra ID.

## Upgrading

Unpack the newer bundle and run `sudo ./upgrade.sh`. It stops the service, installs the new wheels, takes an encrypted
backup, migrates the database, confirms the schema, and starts the service again. If the migration fails it leaves the
service stopped and prints the exact restore command ([`operations.md`](operations.md)).

## What has and has not been tested

The bundle build, `install.sh`, the generated environment, the database creation, `doctor` and the service start are
exercised in CI with a trial install (no root, no systemd). The systemd units are checked with `systemd-analyze verify`.
They have **not** been run on a freshly installed RHEL or Ubuntu server with real systemd and `runuser` in this
project's CI; do that once per OS you support, and run `systemd-analyze security sutra` to review the confinement.
