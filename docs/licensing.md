# Licence keys

A licence key switches modules on for one customer. It is checked on the customer's own server, against the vendor's
public key, with no network call, so it works on an air-gapped plant network.

## For the vendor (Sutra)

```
python -m sutra licence keygen --out ./vendor-keys        # once; keep sutra-licence-private.pem offline
cp vendor-keys/sutra-licence-public.pem sutra/data/licence_public.pem   # before building a release
python -m sutra licence issue --private-key vendor-keys/sutra-licence-private.pem \
    --customer "Vindhya Power" --id C-2027-014 --modules M-BRD,M-RC,M-PJ,M-OT --expires 2028-03-31
```

`--modules *` licenses every module the release contains. The command prints one line, `SUTRA1.<payload>.<signature>`;
send that line to the customer. This repository ships **without** a public key: a release cannot verify keys until the
vendor adds theirs, and an installation without one says so on the Licences tab and refuses to install a key.

## For the customer's administrator

Administration → Licences → paste the key → Install. Or on the server: `python -m sutra licence install @key.txt`.
`python -m sutra licence show @key.txt --public-key vendor-public.pem` checks a key without installing it.

| State | What happens |
|---|---|
| Valid | Modules named in the key can be on. A warning shows in the sidebar for administrators and everyone else for the last 30 days. |
| Grace (30 days after the expiry date) | Modules stay on. The sidebar says the licence expired. |
| Expired, invalid, or no key when `SUTRA_REQUIRE_LICENCE=1` | Only Administration is on, so a new key can always be installed. Nothing is deleted. |
| No key, `SUTRA_REQUIRE_LICENCE` unset | Every built module is on and the Licences tab says "evaluation". |

The per-module switch on the Licences tab still lets an administrator turn a bought module off; it cannot turn on a
module that is not in the key. The installer sets `SUTRA_REQUIRE_LICENCE=1`.

## Limits

* A key is not tied to a machine. It can be copied to a second server; the customer name is shown on the Licences tab
  and recorded in the audit log (`admin.licence_installed`), and the contract covers the rest.
* The key sets modules and dates only. It does not cap hosts or users.
* Nothing here is encryption of the product: the code is open to the customer. The key is a contractual switch, not DRM.
