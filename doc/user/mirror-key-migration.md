# Signing-key migration and incident rollout

This guide separates deploying the source-code protections, moving signing
material, and responding to keys that may already have been disclosed. Moving a
key does **not** revoke it, rotate it, prove that nobody downloaded it, or finish
an incident. Perform operational steps only on environments you administer.

## New layout and affected processes

For a public mirror `/srv/mirror`, new init/clone commands use:

```text
/srv/mirror/                  public metadata, packages and install scripts
/srv/mirror.keys/             private signing material (0700; files 0600)
```

The same resolver is used by local mirror signing commands and `tiup-server`.
The default follows the resolved public mirror path, so a symlink alias for the
mirror does not select a different default key store. `--key-dir` can choose
another non-overlapping private directory. An explicit directory inside the
mirror, including through existing symlink ancestors or filesystem aliases, is
rejected. A key directory containing the public mirror is also rejected.

Init/clone require a fresh key destination. Neither a re-clone nor a retry after
a failed initialization silently overwrites existing key material; retain and
inspect partial results privately before choosing a fresh destination. Do not
restore the old behavior by copying keys back into the public tree.

## 1. Inventory and contain before migration

1. Inventory the actual mirror root, every signing process, role and owner key
   store, startup arguments, filesystem aliases, backups, proxy roots, storage
   sync jobs and CDN origins. Record public KeyIDs/fingerprints, not private key
   contents. A custom legacy location needs an explicit `--from` below.
2. Stop anonymous access to private material at every serving layer, not just
   `tiup-server`: reverse proxies, nginx, object storage, cached/CDN copies,
   aliases and archives can otherwise remain exposed. Configure allow/deny rules
   for the actual deployment; do not assume an example filename covers all keys.
3. Stop HTTP/static publishing, automated sync and signing/rotation processes
   before moving files. The migration command is an offline operation, not a
   coordinator for concurrently running writers or remote publishers.
4. Retain needed evidence and an access-controlled private backup outside all
   publishing trees. Preserve role/public fingerprints and metadata versions for
   the later comparison. Never attach private keys to logs, tickets or reports.

## 2. Deploy tools and explicitly move the keys

Install the updated TiUP CLI and server together. New startup refuses a legacy
`<mirror>/keys` path instead of silently ignoring it or selecting new keys. Even
if `--key-dir` already points elsewhere, an old in-root `keys` path must be
removed through a reviewed migration or private archival step. Do not delete a
key store just to bypass the startup error.

For the default legacy layout, while publishers and signers are stopped:

```bash
tiup mirror migrate-keys /srv/mirror
```

For another legacy source or an explicitly selected destination:

```bash
tiup mirror migrate-keys /srv/mirror \
  --from /srv/mirror/old-signing \
  --key-dir /srv/private/mirror-signing
```

The source must be a real directory containing only valid private-key files and
directories. Symlinks, special files, invalid/unknown files and empty key stores
are rejected for manual inspection; nothing is silently discarded. The
destination must not exist and must be separate from both the public mirror and
the old key directory.

Migration reserves a new 0700 private container, then atomically renames the
whole old key tree into its `keys` child. Thus a default migration produces
`/srv/mirror.keys/keys/<original-key-filenames>`. Recursive loading supports both
that migrated layout and the flat layout of a new mirror. It preserves key bytes
and filenames, tightens directory/file modes to 0700/0600, and checks the key tree
again. It does not generate keys, alter public metadata or re-sign anything.

The source and destination must be on the same filesystem. A failed atomic
rename leaves the source intact and removes only the newly reserved, empty
destination; there is no copy/delete fallback. Use the default sibling location
or choose a private same-filesystem destination. Moving to another filesystem
requires a separately controlled offline transfer and verification, not forcing
this command or deleting the original first.

If verification fails **after** the move, the error identifies where the keys
remain privately stored. Keep publishing stopped, inspect and repair that private
store, and verify identities before restarting. The tool deliberately does not
roll the keys back into an HTTP-served location. A destination collision never
overwrites the existing destination.

## 3. Reconnect signing and publish only public output

For the default sibling location, the updated CLI and server discover the keys
automatically after migration. For a custom location, update every process:

```bash
tiup mirror publish <component> <version> <tarball> <entry> \
  --key-dir /srv/private/mirror-signing
tiup-server /srv/mirror --key-dir /srv/private/mirror-signing
```

Update service-unit mounts, permissions, automation and operator commands too.
Owner keys under `$TIUP_HOME/keys` are a separate store; keep that profile private
and use the existing `--key` option where a signing command needs an owner key.
Do not assume moving mirror-role keys also moves every operator's owner key.

Before resuming, compare the original key-file hashes and derived public
fingerprints, role membership, thresholds and all public metadata hashes/versions.
A location-only migration must not change the trust identity or signed bytes.
Exercise a normal local publishing/verification workflow with the private store.

Point HTTP/nginx document roots and object-storage/CDN sync sources at
`/srv/mirror` only. Do not serve `/srv`, `/srv/mirror.keys`, a private backup, or
`$TIUP_HOME`. For offline distribution, archive only the public directory:

```bash
tar -C /srv -czf mirror-public.tar.gz mirror
```

Review pre-existing private copies, hard links, symlinks and backup archives in
the public tree separately. Neither directory separation nor the static handler
detects arbitrary copied credentials. Remove known leaked object/CDN copies and
invalidate relevant caches through the deployment's normal controls. Public
symlinks and directory index pages are no longer supported by `tiup-server`;
replace them with regular public files and explicit file URLs.

## 4. Revoke/rotate disclosed keys and verify the real deployment

Treat any previously disclosed private key as compromised. Use the established
TiUP root/role/owner revocation and rotation procedure: preserve required signing
thresholds and the signed root-update chain, distribute the new trust metadata,
update legitimate signing processes, and verify that superseded keys are no
longer authorized. Do not just delete a file, arbitrarily replace `root.json`, or
invent a new signature protocol. A storage migration alone does none of this.

The deployment owner should retain separate completion evidence for:

- Anonymous GETs through each actual entry point: a public metadata control
  works, known old paths and actual new-key paths are denied, and no denied path
  is fetched from an upstream source. Inspect minimized response classifications,
  never publish any returned private bytes. Test filenames and aliases that the
  deployment really uses; a 403/404 for one old filename is not universal proof.
- The final role/owner KeyIDs and thresholds, a successful authorized publication,
  and rejection of signatures by revoked keys after clients consume the required
  metadata updates.
- Supported old-client/cache states and fresh clients following the valid trust
  chain, verifying metadata and package hashes, and downloading normal public
  files. A successful upload alone is not client trust-chain validation.
- Consistent server/proxy/storage/CDN configuration, cache cleanup, least-privilege
  private-store access and explicit custody/backup ownership.
- Historical exposure/access assessment and incident decisions. Current path
  denial cannot prove that a key was never downloaded in the past.

The source PR's local and CI fixtures validate code and migration behavior only.
Production containment, rollout, rotation, historical assessment and owner
acceptance remain operational gates and must not be marked passed from those tests.
