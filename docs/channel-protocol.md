# Channel protocol

rootroll consumes a four-role signed channel plus optional delegated
targets. Signatures in this repository are HMAC-SHA256 over the canonical
JSON of the envelope's `signed` object (`sort_keys=True`, no extra
whitespace, UTF-8). Key material lives in `fixtures/keys.json`. Count
distinct `keyid`s that both verify and belong to the role; repeating the
same key does not meet a threshold of two.

## File layout

When the trusted root has `consistent_snapshot: true` (all fixtures here do):

- `metadata/timestamp.json` is unversioned.
- `metadata/{version}.root.json` is the root at that version; `metadata/root.json` is a copy of the latest.
- `metadata/{version}.snapshot.json`
- `metadata/{version}.targets.json`
- `metadata/{version}.delegations.{name}.json`

A snapshot `meta` map uses the logical names `root.json`, `snapshot.json`,
`targets.json`, and `delegations.{name}.json`. The timestamp binds the
snapshot by version, sha256, and length. The snapshot binds every other
metadata file the client will read (including delegated targets) the same
way. Each targets entry binds a payload by sha256 and length.

## Refresh order

Use `--now` as the only clock. A metadata file whose `expires` is less
than or equal to `--now` is expired.

1. Load the trusted root from the store. If it is already expired, refuse.
2. Root chain. Let `N` be the highest `{version}.root.json` on the remote
   (or `root.json`'s version if versioned files are missing). For every
   version `v` from `trusted_version + 1` through `N`, load that exact
   versioned file. The file must be signed by the *currently trusted*
   root's root role (threshold of unique keys). After it is accepted it
   becomes the current root and must also satisfy its *own* root
   threshold, must not skip versions, and must not be expired. A new
   root signed only by keys that the previous root did not list is
   rejected. Equal version requires byte-identical content.
3. Timestamp. Verify with the current root's timestamp role. Its version
   must be greater than or equal to the trusted timestamp; equal version
   requires byte-identical content. It must not be expired. The snapshot
   file that is loaded must match `snapshot_version`, `snapshot_hash`,
   and `snapshot_length`.
4. Snapshot. Verify with the snapshot role. Version must be greater than
   or equal to the trusted snapshot and must match the timestamp's
   `snapshot_version`. Equal trusted version requires byte identity.
   It must not be expired.
5. Top-level targets. Load the consistent filename, bind hash/length/version
   from `snapshot.meta["targets.json"]`, verify with the targets role,
   enforce monotonic versions and expiry the same way.
6. Delegations. A target path may be signed by a delegated role only when
   every ancestor's `paths` allows that path. A pattern `packages/team/`
   or `packages/team` matches `packages/team` and `packages/team/...`,
   and must not match `packages/team-evil/...`. Paths containing `..`, a
   leading slash, or a backslash are rejected. If a delegated targets
   file lists any path its role does not allow, refuse the whole refresh;
   do not install sibling files from that snapshot. If a role is
   `terminating: true` and its `paths` match the target, later sibling
   roles are not consulted, even when the terminating role does not list
   the file; the unmatched path is simply not installed and the rest of
   a valid refresh may still be accepted. A non-terminating role that
   does not list the file may fall through to a later sibling whose
   paths also allow it. Delegated metadata itself is bound by the
   snapshot `meta` entry `delegations.{name}.json`.
7. Payloads. Only after metadata is fully accepted, copy a payload into
   `--install-dir` when its bytes match the targets hash and length.
   Then persist the new trusted metadata into `--store`.

A remote that is byte-for-byte the same as the trusted store is a
successful no-op (exit 0, installed artifacts unchanged).

If the store, keys, clock, or remote directory cannot be read, or the
trusted root is missing, the process exits 2 and should not write
`--report`.
