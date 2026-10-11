# Operations: backups, restore and upgrades

Everything here runs on the Sutra server, offline. `SUTRA_WORKSPACE` (default `./workspace`) is the data folder;
`SUTRA_DATABASE_URL` defaults to `sqlite:///<workspace>/sutra.db`.

## What a backup holds

One file, `sutra-backup-<UTC time>.tar.gz` (`.enc` added when encrypted), made by:

```
python -m sutra backup create --passphrase-file /etc/sutra/backup.pass --out /var/backups/sutra --keep 14
```

It contains the database (taken with SQLite's online backup, so the service can keep running), the workspace files
(uploaded evidence, datasets, intel feeds, the generated `.secret_key`) and a manifest with a SHA-256 for each file, the
schema revision and the Sutra version. It does not contain `staging/` (half-finished uploads), `backups/` or the SQLite
`-wal`/`-shm` files.

* **Encryption.** With a passphrase the file is AES-256-GCM (key from scrypt). Without one the file is plain and the
  command says so: it holds the database and the server secret. Keep the passphrase somewhere other than the server.
  Sutra cannot recover a lost passphrase.
* **Server secret.** If you set `SUTRA_SECRET_KEY` in the environment instead of using the generated file, that value
  is not in the backup. Store it with your other secrets. Without it, stored scanner credentials cannot be decrypted
  after a restore and must be entered again; nothing else is affected.
* **PostgreSQL.** `backup create` refuses (it does not pretend). Dump the database with
  `pg_dump --format=custom "$DB" > sutra.dump`, and run `backup create --files-only` for the workspace. Restore with
  `pg_restore`, then `backup restore` of the files-only archive.
* **Schedule.** Run it from cron or a systemd timer (nightly is typical) and copy the files off the server.

## Check a backup (do this regularly)

```
python -m sutra backup list --out /var/backups/sutra
python -m sutra backup verify /var/backups/sutra/sutra-backup-20270102T030000Z.tar.gz.enc --passphrase-file ...
```

`verify` decrypts, re-hashes every file and fails on any mismatch, any file missing from the manifest, or any unsafe
path inside the archive. A backup you have never restored is a hope, not a backup: restore one to a scratch folder
(`--workspace /tmp/sutra-test`) at least once per quarter.

## Restore

1. Stop the service (`systemctl stop sutra`). Restore refuses to run while the database is in use.
2. `python -m sutra backup restore <archive> --passphrase-file ... --force`
3. Start the service.

Restore checks every checksum before it changes anything. With `--force` the current database and files are moved to
`<workspace>/pre-restore-<time>/`, never deleted. A backup made by an older release is migrated forward
automatically; a backup from a newer schema than this release knows is refused (install the newer release first).

## Upgrade

```
python -m sutra upgrade --check     # exit 1 if a migration is pending
systemctl stop sutra
pip install --no-index --find-links wheelhouse sutra   # or your usual way of installing the new release
python -m sutra upgrade             # backs up, migrates, confirms the schema is at head
systemctl start sutra
```

`upgrade` takes a backup first and stops with a message if it cannot (nothing is changed). If the migration fails it
prints the exact `backup restore` command to go back. For PostgreSQL take a `pg_dump` yourself and pass
`--db-backed-up`.
