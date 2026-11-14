# Incidents still reproducible against this tree

These are production tickets, not a checklist of reason codes. Each one
still succeeds when the current client is pointed at the listed case
directory (copy the case's `store` to a writable temp directory first).

## INC-2147 — downgrade of an already installed package

A host with `packages/app.bin` 3.1.0 pulled a freshly signed timestamp
and then installed 2.9.0. The timestamp version had moved forward; the
snapshot and targets behind it were an older consistent set that the
host had already retired. Reproduce with `fixtures/cases/rollback-targets`.

## INC-2188 — stale mirror after expiry

A mirror stopped rotating timestamp files. Weeks after `expires`, hosts
that still talked to that mirror accepted the signed but expired
timestamp and refreshed as if it were current. Reproduce with
`fixtures/cases/freeze-expiry`.

## INC-2201 — mix-and-match across two valid histories

An attacker served a new, valid timestamp together with a *different*
snapshot that was also validly signed by the snapshot key, but was not
the snapshot the timestamp hashed. The client installed the mixed view.
Reproduce with `fixtures/cases/mix-and-match`.

## INC-2214 — delegated key published outside its path

The `pkg-team` role is only supposed to sign under `packages/team`
(meaning that directory prefix, not a neighboring name). A compromised
team key published `packages/team-evil/x.bin` and the client installed
it. Reproduce with `fixtures/cases/path-escape`.

## INC-2230 — payload bytes did not match targets

Metadata was fully signed. The file on the mirror under `packages/app.bin`
was not the digest recorded in targets. The client copied the mirror
bytes anyway. Reproduce with `fixtures/cases/payload-mismatch`.
