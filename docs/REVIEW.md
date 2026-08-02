# Aegis System Review

**Date:** 2026-08-02 · **Status:** the roadmap in §4 has been implemented; see
the checkboxes against each finding.

**Reviewed at:**

| Repo | Commit |
|---|---|
| `fudoniten/aegis` | `b33fb0b` |
| `fudoniten/aegis-tools-system` | `2b199d4` |
| `fudoniten/aegis-tools-user` | `d1947ca` |
| `fudoniten/aegis-secrets` | `4ecac5e` |

Companion document: [`kerberos-realm-management.md`](./kerberos-realm-management.md) — design for the
realm-management feature.

---

## Summary

The architecture is sound. age everywhere, public repos, a per-host manifest that Nix reads at
evaluation time, and two-phase decryption so the KDC can hold a role key that reads every host's
keytab. The `roles` generalization — using `domain-*` and `site-*` roles as group membership markers
— is a capability model, and it is the part worth building more on.

The problem is not architectural. It is that **the system is half-built in three places at once, and
the three halves disagree with each other.** Most findings below fall out of that.

Findings are given stable IDs (`B*` bugs, `R*` recoverability, `S*` simplification) so they can be
referenced from commits and issues.

| Severity | Meaning |
|---|---|
| **Critical** | Silent data loss, silent security failure, or a component that cannot work at all |
| **High** | Breaks in normal use; workaround exists but is not obvious |
| **Medium** | Correctness or usability defect with a clear workaround |
| **Low** | Papercut |

---

# 1. Correctness bugs

## B1 — `except SystemExit` never fires; one bad host aborts the whole build

**Severity:** Critical · **Repo:** `aegis-tools-system`

`get_host_age_pubkey` signals failure with `typer.Exit`, and five call sites guard it with
`except SystemExit` (`aegis/cli.py:192, 268, 358, 518, 717`). Verified against the installed
library:

```
typer.Exit MRO: ['Exit', 'RuntimeError', 'Exception', 'BaseException', 'object']
issubclass(typer.Exit, SystemExit) -> False
```

`typer.Exit` derives from `RuntimeError`, not `SystemExit`. Every "skip this host and continue" path
is therefore dead code — the exception propagates and kills the run.

With 36 hosts and no `--continue-on-error`, a single host missing `age_pubkey` aborts
`build-ssh-host-keys`, `build-nexus-keys`, `build-keytabs`, `build-role-keys` and
`build-user-secrets`.

**Fix:** raise a dedicated `AegisError` internally; convert to `typer.Exit` only at the CLI
boundary. Catch `AegisError` at the per-host loop.

- [x] Fixed

## B2 — Keytabs deploy corrupted

**Severity:** Critical · **Repos:** `aegis`, `aegis-tools-system`

`encrypt_age_binary` (`aegis/crypto.py:82-102`) base64-encodes its input and prepends a literal
`base64:` sentinel. The manifest records `encoding = "base64"`, and `modules/secrets.nix` faithfully
parses that into a read-only option (`secrets.nix:650-663`) — **and then never uses it.**
`decryptScript` (`secrets.nix:62-112`) runs `age --decrypt` and writes the result verbatim.

So `/etc/krb5.keytab` receives the ASCII string `base64:BQIAAA…` rather than a keytab. Every
consumer of a keytab is broken.

**Fix:** preferably eliminate the sentinel entirely — see B3. Otherwise, teach `decryptScript` to
strip the prefix and base64-decode when `encoding = "base64"`.

- [x] Fixed

## B3 — `init-realm` produces realms that `build-keytabs` cannot read

**Severity:** Critical · **Repo:** `aegis-tools-system`

`init-realm` reads the realm master key with `.read_text()` and encrypts it with the *text*
`encrypt_age` (`aegis/cli.py:1788-1796`). `build-keytabs` decrypts it with `decrypt_age_binary`
(`aegis/cli.py:488`), which looks for the `base64:` sentinel, does not find it, and falls back to
`content.encode("utf-8")` — mangled key material. The `kstash` realm key is binary, so
`.read_text()` will likely raise `UnicodeDecodeError` before that point anyway.

`import-kerberos-realm` does this correctly (`encrypt_age_binary`, `aegis/cli.py:1125`).

**Net effect: imported realms work, freshly-created realms do not.** All three realms currently in
this repo were imported, which is why this has not surfaced.

**Fix:** route all Kerberos material through one binary-clean path. Best option is to make
`crypto.encrypt_age`/`decrypt_age` binary-clean throughout (`subprocess` with `text=False`) and
delete `encrypt_age_binary`/`decrypt_age_binary` and the `base64:` sentinel. age handles binary
payloads natively; the sentinel exists only because `decrypt_age` passes `text=True`. This also
resolves B2.

- [x] Fixed

## B4 — `build-keytabs` cannot run at all against this repo

**Severity:** Critical · **Repos:** `aegis-tools-system`, `aegis-secrets`

`build-keytabs` groups hosts by realm via `HostConfig.domain` → `DomainConfig.realm`
(`aegis/cli.py:431-445`). In this repo:

- 3 of 36 host configs carry a `domain` field
- `src/domains/` **does not exist**

So `hosts_by_realm` is empty, the command prints `No hosts with Kerberos realms found.` and returns.

Domain membership *is* recorded — as `domain-sea.fudo.org`, `domain-fudo.org`, `domain-informis.land`
roles with correct host lists. There are two representations of the same fact and the one the code
reads is empty.

**Fix:** pick one representation. Recommended: declare `domains` in the realm's `realm.toml` (see
the realm-management design) and derive host membership from the existing `domain-*` roles. Then
delete `DomainConfig` and the `HostConfig.domain` field.

- [x] Fixed

## B5 — The Kerberos toolchain is wired to the wrong Kerberos

**Severity:** Critical · **Repo:** `aegis-tools-system`

`flake.nix` puts `pkgs.krb5` in `runtimeInputs`. That is MIT Kerberos. Every vendored Ruby script
requires **Heimdal**:

| Used by scripts | MIT equivalent |
|---|---|
| `kstash --key-file=` | does not exist (`kdb5_util stash`) |
| `kadmin --local --config-file=` | `kadmin.local`, different flags |
| `kadmin ... dump --decrypt` | different dump format |
| `kadmin ... merge <file>` | no equivalent |
| `dbname = sqlite:` | not supported |

Nothing Kerberos-related can work until this is `pkgs.heimdal`.

- [x] Fixed

## B6 — Phase-2 user secrets cannot work as written

**Severity:** High · **Repo:** `aegis`

`mkUserSecretsService` runs with `User = username` (`modules/secrets.nix:290-311`). It needs
`/run/aegis/users/<user>/.key`, which phase 1 writes as `root:root 0400`
(`secrets.nix:921-932`) into a directory `decryptScript` creates as `root:root 0750`
(`secrets.nix:83-85`).

The user cannot traverse the directory, let alone read the key — and the service's first action is
`mkdir -p "$TARGET_DIR/env"` inside that root-owned directory.

`PLAN.md` lists this as unchecked work, but the code reads as finished. That mismatch is its own
hazard.

**Fix:** either run the phase-2 service as root and `chown` the outputs to the user, or make the
user key readable by the target user (`user = username`, `group = username`, mode `0400`) and the
parent directory `0700 <user>:<user>`.

- [x] Fixed

## B7 — sshd races its own host keys

**Severity:** High · **Repo:** `aegis`

SSH key services are `wantedBy` / `before` `aegis-phase1.target`, and `aegis-phase1.target` is
`before multi-user.target`. `sshd.service` is also merely `wantedBy = multi-user.target`. There is
**no ordering edge between them**, so nothing prevents sshd starting before
`/etc/ssh/ssh_host_ed25519_key` exists.

**Fix:** when the module manages SSH host keys, inject

```nix
systemd.services.sshd = {
  after = [ "aegis-phase1.target" ];
  requires = [ "aegis-phase1.target" ];
};
```

More generally, the module should be able to wire *any* manifest-declared consumer to the right
phase target rather than requiring every service to be hand-wired.

- [x] Fixed

## B8 — The keytab is decrypted twice, to the same path

**Severity:** High · **Repo:** `aegis`

`modules/auto-secrets.nix:121-142` globs top-level `*.age` into generic secrets — picking up
`keytab.age` → `/run/aegis/keytab` — *and* separately enables `keytab.enable` with the same default
target. Two oneshot units, both `rm -f`-then-decrypt, same file, no ordering between them.

Resolved for free by S1 (delete `auto-secrets.nix`).

- [x] Fixed

## B9 — All three NixOS VM tests would fail

**Severity:** High · **Repo:** `aegis`

`dryRun` defaults to `true` (`modules/secrets.nix:438`), and none of `tests/basic.nix`,
`tests/two-phase.nix`, `tests/service-dependency.nix` set it to `false`. Every
`machine.succeed("test -f /run/aegis/...")` checks a path that dry-run redirects to
`/run/aegis-dry-run/`. In `two-phase.nix` the phase-2 `identity` path is likewise redirected, so
phase 2 cannot find its key.

These tests have never been run green. `PLAN.md` confirms — "NixOS VM tests" is unchecked.

**Fix:** set `dryRun = false` in all three tests, and add a fourth that asserts dry-run *does*
redirect. Then wire `nix flake check` into CI so the module is actually gated.

Evaluating them also hit an infinite recursion that predates the tests: `secretsPath` defaulted to
`hostSecretsPath`, which read `cfg.secretsPath`. Neither option being set — as in all three tests —
made the manifest lookup diverge.

- [x] Fixed — `dryRun` now defaults to false, the tests set it explicitly, `secretsPath` is
  nullable, and `tests/manifest.nix` covers the manifest path end to end. **Not yet executed:** no
  Nix was available in the implementation environment, so `nix flake check` still needs to run.

## B10 — Assorted

**Severity:** Medium / Low

| ID | Finding | Location |
|---|---|---|
| B10.1 | `import-secret` and `aegis-user add-file` use `.read_text()` — any binary secret (p12, keytab, DER cert) errors or is corrupted | `aegis-tools-system/aegis/cli.py:1194`, `aegis-tools-user/aegis_user/cli.py:220` |
| B10.2 | `aegis list` / `aegis verify` glob only `build/hosts/<h>/*.age`, missing `ssh/`, `roles/`, `users/` — `aegis list nostromo` reports 1 file where there are 11 | `aegis/cli.py:2067, 2091` |
| B10.3 | `_is_aegis_repo` is `A or (B and C)` by Python precedence, so *any* directory containing `src/` qualifies; running `aegis` in the wrong repo scaffolds an aegis tree into it via `ensure_structure()` | `aegis/cli.py:19-25` |
| B10.4 | Dry-run flattens every target to `${dryRunPath}/${baseNameOf target}` — same-basename secrets from different directories silently collide | `modules/secrets.nix:58-59` |
| B10.5 | `restartIfChanged = true` plus an `ExecStop` that `rm -f`s the target means `nixos-rebuild switch` deletes live secrets; if the new unit fails to start they are not restored | `modules/secrets.nix:327, 341` |
| B10.6 | `role_build_path(role_name)` ignores its argument and returns `build/roles`; callers append the name themselves | `aegis/config.py:288-290` |
| B10.7 | `list_dnssec_domains` round-trips domains through `.replace(".", "_")` in both directions — lossy for any domain containing an underscore | `aegis/config.py:344-350` |
| B10.8 | Both tool READMEs document commands that do not exist: `import-ssh-key` (actually `import-ssh-host-keys`), `build-ssh-keys` (`build-ssh-host-keys`), `init-role kdc kdchost` (takes one argument) | `aegis-tools-system/README.md`, `aegis-secrets/flake.nix` devShell banner |
| B10.9 | `aegis-user` has no `edit` command (listed in `PLAN.md`), and users cannot decrypt their own secrets by design — a typo'd token is invisible until deployment fails | `aegis-tools-user/aegis_user/cli.py` |

- [x] Triaged — B10.1, B10.2, B10.3, B10.6, B10.7, B10.8 fixed; B10.4 and B10.5 fixed in the module; B10.9 (`aegis-user edit`) not done.

---

# 2. Recoverability and foot-guns

This section answers the question "what happens if I fumble, and can I get my secrets back?"

## R1 — `build/` is not a build directory; it is primary storage

**Severity:** Critical · **Repo:** `aegis-secrets`

The name says "regenerable artifact." The contents say otherwise:

| Secret | In `src/`? | In `build/`? |
|---|---|---|
| SSH host private keys | **no** | yes — only copy |
| Nexus DDNS keys | **no** | yes — only copy |
| DNSSEC KSK private keys | no (only keytag metadata) | yes — only copy |
| Per-host role key copies | derivable from `keys/roles/` | yes |
| Target path / user / group / mode for every secret | **no** | yes — only copy (`secrets.toml`) |
| Kerberos principals | yes | — |

`rm -rf build/ && aegis build` does **not** restore the infrastructure. It mints brand-new SSH host
identities (breaking `known_hosts` and every SSHFP record), brand-new DDNS keys, and loses every
custom target path ever set via `--target/--user/--group/--mode`, because those flags are consumed at
generation time and persisted only into `build/hosts/<h>/secrets.toml`.

**Fixes, both worth doing:**

1. **Rename it.** `deploy/` or `out/` — anything that does not read as "safe to delete."
2. **Make placement declarative** (see S3). Target/user/group/mode belong in
   `src/hosts/<host>.toml`, not in CLI flags at generation time.

The end state to aim for: **`build/` is a pure function of `src/` plus existing key material.**
Today it is a mutable accumulator, which is precisely why nothing in the system can answer "is this
consistent?"

- [x] Addressed — renamed to `deploy/`, placement moved to `src/hosts/*.toml`.

## R2 — The admin key is an unbacked single point of failure

**Severity:** Critical · **Repos:** `aegis-tools-system`, `aegis-secrets`

`get_admin_public_key()` (`aegis/crypto.py:179-203`) derives the recipient from the local
`~/.config/aegis/key.txt`. Encrypted for the admin **and nobody else**:

- every role private key — `keys/roles/*.age`
- every user private key — `keys/users/*.age`
- every realm master key — `src/kerberos/realms/*/realm.key.age`
- all 291 Kerberos principals across the three realms

Lose that file and hosts keep running — they hold their own copies — but you can never again add a
host to a realm, add a host to a role, onboard a user, or regenerate a keytab. Recovering Kerberos
would mean rebuilding all three realms from scratch and re-keying every host.

Compounding this: `keys/admin.pub` exists in this repo and `config.py:310-312` has an accessor for
it — and **nothing ever reads it.** There is no check that the local key matches the one the repo was
built with. Using a different admin key by accident silently produces files the real admin cannot
read.

**Fix:** make the admin recipient a *set*, read from the repo (`keys/admin/*.pub`), used by every
`encrypt_age` call, and validated at startup against the local private key. A second admin key held
offline (paper, YubiKey, HSM) then makes losing the daily driver a non-event.

- [x] Addressed — admin recipient set in `keys/admin/*.pub`, validated against the local key.

## R3 — Removal is not revocation

**Severity:** High · **Repo:** `aegis-tools-system`

`remove-host-from-role` (`aegis/cli.py:1902-1930`) deletes `build/hosts/<h>/roles/<role>.age` and
drops the host from the config. But:

- the role keypair is unchanged
- the host still holds the plaintext role key at `/run/aegis/roles/<role>`
- because `build/` is committed to git, the deleted ciphertext is one `git show` away, forever

The same applies to users. Editing a user's `hosts` list leaves `build/hosts/<oldhost>/users/<user>/`
fully populated, and `build-user-secrets` never deletes it. `Manifest.add_or_update` only ever
accumulates; `Manifest.remove` exists (`aegis/manifest.py:134-141`) but has no caller, so secrets a
user deletes from their own repo live on their hosts indefinitely.

Missing entirely: `revoke-user-access`, `grant-user-access` (both listed in `PLAN.md`),
`remove-host`, `remove-user`, `remove-secret`.

**Fix:** revocation must mean *rotate the key and re-encrypt*, never *delete the file*. Add
`aegis revoke-*` commands that rotate the affected role/user key, re-encrypt for the remaining
members, and print an explicit warning that any already-deployed plaintext must be considered
compromised until every remaining host has been redeployed.

- [ ] Not addressed — `aegis check` now *reports* stale role keys and orphaned user secrets, but there are still no `revoke-*` commands that rotate.

## R4 — No re-key path, and `--force` is a loaded gun

**Severity:** High · **Repo:** `aegis-tools-system`

If a host is reinstalled and gets a new master key, `set-master-key` updates the config — and then
nothing re-encrypts the existing secrets. The only lever is `--force`, which on
`build-ssh-host-keys` and `build-nexus-keys` **generates new key material** rather than re-encrypting
the existing material for the new recipient.

`--force` conflates two very different operations. Split it:

| Flag | Meaning |
|---|---|
| `--reencrypt` | same plaintext, new recipient set — safe, idempotent, almost always what you want |
| `--rotate` | new key material — should require confirmation and print what breaks (SSHFP records, `known_hosts`, DDNS registration) |

And add `aegis rekey-host <host>`: decrypt everything with the admin key, re-encrypt for the new host
pubkey, touch no key material.

- [x] Partly addressed — `--force` split into `--rotate` (confirmed, destructive) and `aegis reencrypt` (safe). `aegis rekey-host` not implemented; `reencrypt --host` covers the same ground.

## R5 — Ordering traps: every build step creates, none reconcile

**Severity:** High · **Repo:** `aegis-tools-system`

Every build step is "create if missing," never "reconcile." That makes ordering silently
load-bearing:

- **`init-role kdc` and `add-host-to-role kdc <host>` must precede `build-keytabs`.** Otherwise
  `kdc_role_pubkey` is `None` (`aegis/cli.py:448-453`), keytabs are encrypted without the KDC as a
  recipient, and the KDC principals file is skipped with a warning. Re-running `build-keytabs`
  **does not repair this** — the keytab file exists, so it is skipped (`aegis/cli.py:554-557`), and
  that `continue` also skips the manifest update, so a host can end up with a keytab and no manifest
  entry.
- `build-role-keys` must precede anything needing role pubkeys.
- `init-host` → `set-master-key` → `build`; skipping the middle step currently aborts the entire
  build (B1) rather than skipping the host.

`aegis build` gets the internal order right, so this only bites when running individual steps — but
since `build` also never repairs anything, recipient-set drift is permanent once introduced.

### R5.1 — Add `aegis check`

**This is the single highest-value addition to the system.** A reconciler that reports drift rather
than creating files:

```
$ aegis check
  ✗ thing-3: no master key set (src/hosts/thing-3.toml has no age_pubkey)
  ✗ nostromo: keytab not encrypted for role 'kdc' (recipients: host, admin)
  ✗ role 'domain-fudo.org': 6 members, 4 have key files
  ✗ build/hosts/clunk/: host not in src/hosts/ (stale, 11 files)
  ✗ user niten: 3 secrets in build/hosts/rama/ not present in user repo
  ✗ SEA.FUDO.ORG: 24 hosts in realm, 0 keytabs built
```

Paired with `aegis reencrypt [--host X]` — which fixes recipient drift without touching key
material — this removes most of the operational anxiety. Right now there is no way to ask the system
whether it is consistent.

- [x] `aegis check` implemented
- [x] `aegis reencrypt` implemented

---

# 3. Simplification

## S1 — Collapse three secret-delivery mechanisms into one

**Repo:** `aegis`

There are three ways a secret reaches a host, and they disagree:

| Mechanism | Source of truth | Where secrets land |
|---|---|---|
| `aegis.secrets.secrets` | hand-written Nix | wherever you say |
| `aegis.secrets.autoConfigureFromManifest` (default **off**) | `secrets.toml` | manifest's `target`/`user`/`group`/`mode` |
| `aegis.autoSecrets` | globs `build/hosts/<h>/` | `/run/aegis/<name>`, root:root 0400 — **manifest ignored** |

The `aegis` README Quick Start recommends `autoSecrets`, the one that discards the manifest.
Concretely: SSH keys land in `/etc/ssh` via `autoSecrets` but `/run/aegis/ssh` via the manifest; the
keytab gets two competing services (B8); every custom `--target/--user/--group/--mode` is silently
dropped.

**Make the manifest the single source of truth.** Delete `modules/auto-secrets.nix` entirely.
`aegis.secrets` reduces to:

```nix
aegis.secrets = {
  enable = true;
  secretsRepoPath = inputs.aegis-secrets;
  masterKeyPath = "/state/master-key/key";
  users = [ "niten" ];
  secrets = { };   # escape hatch for overrides only
};
```

Everything else — SSH keys, keytab, nexus key, roles, arbitrary secrets — comes from `secrets.toml`.
The special-cased `sshHostKeys`, `keytab` and `nexusKey` option blocks (~200 lines of
`modules/secrets.nix`) become one generic entry type with a `kind` field covering the handful of
behaviours that actually differ: SSH's `.pub` sidecar, base64 decoding.

Removes roughly 400 of the 1008 lines in `modules/secrets.nix` and eliminates an entire class of
bug.

- [x] Done — `auto-secrets.nix` reduced to a deprecating shim; the module reads the manifest.

## S2 — Collapse `build-*` / `import-*` into a registry

**Repo:** `aegis-tools-system`

`aegis/cli.py` is 2105 lines, most of it five near-identical pairs (ssh / nexus / keytab / dnssec /
generic × build / import). Each re-implements "resolve host key → encrypt → load manifest → mutate →
save," and each carries its own copy of `--target --user --group --mode`.

One internal helper:

```python
def put_host_secret(repo, hostname, name, content, *, kind, extra_recipients=()):
    """Encrypt for host + admin (+ extras), write, update manifest."""
```

plus a generator registry (`{"ssh": gen_ssh, "nexus": gen_nexus, ...}`) turns those ten commands
into `aegis generate <kind> [host]` and `aegis import <kind> <host> --file ...`. Likely halves the
file.

- [ ] Not done — the `build-*`/`import-*` pairs still duplicate each other. Out of scope for this pass.

## S3 — Placement belongs in `src/`, not in CLI flags

**Repos:** `aegis-tools-system`, `aegis-secrets`

The widest-blast-radius change, and the structural fix behind R1.

Once `--target/--user/--group/--mode` move into `src/hosts/<host>.toml`:

- `secrets.toml` becomes genuinely derived
- `build/` becomes genuinely regenerable for everything except raw key material
- "I changed a target path" stops requiring `--force`, which currently regenerates keys

- [x] Done — placement lives in `src/hosts/<host>.toml`; see `aegis set-placement`.

## S4 — Smaller cleanups

- **`dryRun` defaults to `true`,** which is the wrong default for a system whose failure mode is
  *silent*. A dry-run host still satisfies `aegis-secrets.target`, so dependent services get a green
  light with no secrets present. Either make dry-run **not** satisfy the target, or default it to
  `false` and require opt-in. At minimum, the `aegis` README Quick Start must set `dryRun = false` —
  as written it deploys a non-functional configuration with no error.
- Fix `role_build_path` (B10.6) and `list_dnssec_domains` (B10.7) rather than working around them.
- Add `aegis-user verify` so a user can confirm a secret decrypts without being able to read it back.

- [x] Partly done — `dryRun` now defaults to false and both aliases are fixed; `aegis-user verify` not added.

---

# 4. Suggested order of work

1. **`aegis check`** (R5.1). Before fixing anything, get visibility. You cannot reason about drift
   you cannot see, and this is the direct answer to "I'd hate to lose track."
2. **Multiple admin recipients** (R2). Cheapest possible insurance against the worst outcome.
3. **`typer.Exit` fix** (B1) and **binary/base64 unification** (B2, B3). Small, mechanical, and they
   unblock everything downstream.
4. **`krb5` → `heimdal`** (B5), then the realm work in
   [`kerberos-realm-management.md`](./kerberos-realm-management.md).
5. **Rename `build/` → `deploy/`, move placement into `src/`** (R1, S3). Do this before the tree
   grows further.
6. **Delete `auto-secrets.nix`; manifest becomes canonical** (S1). Then fix the VM tests (B9) so
   they gate the module.

---

# 5. Implementation status

The §4 roadmap was implemented across three commits:

| Repo | What landed |
|---|---|
| `aegis-tools-system` | `AegisError`, binary-clean crypto, admin recipient set, `aegis check`/`reencrypt`/`admin`/`realm`, declarative placement, `deploy/` rename, Heimdal, B10 fixes |
| `aegis` | Manifest-canonical `secrets.nix`, `auto-secrets.nix` reduced to a shim, new `aegis.kdc`, user-secret and sshd fixes, VM tests repaired plus `tests/manifest.nix` |
| `aegis-secrets` | `build/` → `deploy/`, `keys/admin.pub` → `keys/admin/primary.pub`, `realm.toml` for all three realms, flake outputs updated |

### Deliberately not done

- **R3 (removal is not revocation).** `aegis check` now *reports* stale role keys, orphaned user
  secrets and role files left behind by renames, but there are still no `revoke-*` commands that
  rotate the affected key. Rotation needs a policy decision about how to sequence redeployment.
- **R4 (`aegis rekey-host`).** `--force` was split into `--rotate` (destructive, confirmed) and
  `aegis reencrypt` (safe), which covers the host-rekey case; a dedicated command was not added.
- **S2 (collapse `build-*`/`import-*` into a registry).** Not in the §4 roadmap; `cli.py` still
  carries the duplicated pairs.
- **B10.9 (`aegis-user edit`/`verify`).** Untouched.

### What `aegis check` found in this repo

Running it against `aegis-secrets` for the first time reported:

- three hosts with no master key: `clunk`, `paris`, `pselby-work`
- no `kdc` role at all, so every keytab built before creating it would have been unreadable by the KDC
- 32 hosts resolving to a realm, none with a keytab — the consequence of B4
- three `dns-master-*` roles with host members but no public key, alongside orphaned
  `dns-<domain>.age` files with no config: a rename from `dns-*` to `dns-master-*` that only half
  completed

`FUDO.ORG` also holds host principals for 30 `sea.fudo.org` and 2 `informis.land` hosts, which now
have their own realms. `realm.toml` deliberately claims only `fudo.org` for it, leaving those as
stale principals to be cleaned up rather than routing those hosts' keytabs to the wrong realm.

---

## Appendix: verification notes

Claims in this document were verified against the checked-out trees rather than inferred:

- **B1** — `typer` installed and `typer.Exit.__mro__` inspected directly.
- **B3** — confirmed `init-realm` uses `encrypt_age` while `build-keytabs` uses
  `decrypt_age_binary`; confirmed the realm keys currently in this repo carry the `base64:` sentinel
  (i.e. were written by the `import` path).
- **B4** — counted host configs carrying a `domain` field (3 of 36) and confirmed `src/domains/`
  does not exist.
- **B5** — cross-checked every command invoked by the vendored Ruby scripts against Heimdal vs MIT
  krb5 syntax.
- **B9** — grepped all three test files for `dryRun`; none set it.
- **R1** — enumerated `src/` and `build/` to confirm which secret classes exist only under `build/`.
- **R2** — confirmed `keys/admin.pub` has an accessor in `config.py` and zero readers.

Unverified by execution (no Heimdal, no NixOS VM, no host keys available in the review environment):
the runtime behaviour of B2, B6, B7 and B8. These are read from code and are high-confidence, but
each deserves a test that reproduces it before the fix lands.
