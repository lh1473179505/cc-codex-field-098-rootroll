# rootroll

A signed software-channel client. The local `--store` keeps the last accepted
root / timestamp / snapshot / targets metadata plus whatever packages were
installed. A `--remote` directory stands in for the upstream mirror; this
repository does not talk to the network.

```
python -m rootroll status --store fixtures/stores/baseline
python -m rootroll apply \
  --store /tmp/rootroll-store \
  --remote fixtures/cases/legit-patch/remote \
  --keys fixtures/keys.json \
  --now 2026-11-14T05:00:00Z \
  --report /tmp/rootroll-report.json \
  --install-dir /tmp/rootroll-install
python -m rootroll.check_public
```

`apply` exits 0 when the refresh is accepted (including a no-op when the
remote is identical to the store), 1 when the client refuses the remote, and
2 when the store, remote, keys, or clock cannot be read.

The happy path already works. Several attacks documented in
`docs/incidents.md` still go through; the intended channel rules are in
`docs/channel-protocol.md`.
