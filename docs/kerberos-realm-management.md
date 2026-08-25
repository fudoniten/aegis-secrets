# Kerberos Realm Management — Design

**Date:** 2026-08-02 · **Status:** implemented. Section 4 notes how each piece landed; §3's
`realm add-service` is the only command not built (`realm add-principal --host` covers it).

Companion to [`REVIEW.md`](./REVIEW.md). This document proposes the realm-management feature for
`fudoniten/aegis` + `fudoniten/aegis-tools-system`, derived from the working practice encoded in
`fudoniten/fudo-nix-pkgs` (`static/*.rb`) and the `/secrets` scripts preserved in
`fudoniten/secrets-scripts`.

---

## 1. What a realm actually is, per the existing data

Reading the three realms currently in this repo — `SEA.FUDO.ORG` (107 principals), `FUDO.ORG` (164),
`INFORMIS.LAND` (20) — a realm holds four distinct categories of principal. Only one of them is
managed today.

| Category | Examples | Managed today? |
|---|---|---|
| Realm infrastructure | `krbtgt_REALM@REALM`, `kadmin_admin@`, `kadmin_changepw@`, `kadmin_hprop@`, `changepw_kerberos@`, `default@`, `WELLKNOWN_ANONYMOUS@`, `WELLKNOWN_org.h5l.fast-cookie@WELLKNOWN:ORG.H5L` | created once by `kadmin init`, never touched again |
| Host service principals | `host_`, `ssh_`, `nfs_`, `hprop_` + FQDN | yes — via `build-keytabs` |
| Standalone service principals | `postgres_rama.sea.fudo.org`, `postgres_locum.informis.land` | **no** — imported only, cannot create new ones |
| **Cross-realm trust** | `krbtgt_INFORMIS.LAND@SEA.FUDO.ORG` and `krbtgt_SEA.FUDO.ORG@INFORMIS.LAND`, stored under **both** realm directories | **no** — imported only |

### 1.1 The trust mechanism is simpler than it looks

The last row is the interesting one, and the existing data shows the mechanism directly: the *same*
principal name appears under both realms' `principals/` directories.

```
src/kerberos/realms/SEA.FUDO.ORG/principals/krbtgt_INFORMIS.LAND@SEA.FUDO.ORG.age
src/kerberos/realms/SEA.FUDO.ORG/principals/krbtgt_SEA.FUDO.ORG@INFORMIS.LAND.age
src/kerberos/realms/INFORMIS.LAND/principals/krbtgt_INFORMIS.LAND@SEA.FUDO.ORG.age
src/kerberos/realms/INFORMIS.LAND/principals/krbtgt_SEA.FUDO.ORG@INFORMIS.LAND.age
```

Both realms hold both directions — bidirectional trust.

Because principals are stored as `kadmin dump --decrypt` lines (fully-qualified principal name plus
*plaintext* key material), establishing trust reduces to: **create the principal once, write the
identical dump line into both realms' principal directories.** No key negotiation, no shared-secret
ceremony. That makes cross-realm trust a ~20-line operation in this design, which is worth
exploiting.

### 1.2 The filename convention is lossy

Principal files are named by `principal.gsub('/', '_')` — so `krbtgt/INFORMIS.LAND@SEA.FUDO.ORG`
becomes `krbtgt_INFORMIS.LAND@SEA.FUDO.ORG.age`. Reversing that mapping is ambiguous for any
principal containing an underscore, and `kdc-add-principal.rb` uses `.sub` (first occurrence) where
`initialize-kerberos-realm.rb` uses `.gsub` (all occurrences) — an inconsistency waiting to bite on
a multi-component principal.

The design below stores the canonical principal name in a per-realm index rather than encoding it in
the filename.

---

## 2. Storage layout

### 2.1 Add realm metadata

A realm currently carries **zero** metadata. Encryption types and lifetimes are Python defaults
(`aegis/kerberos.py:52, 155`), so `build-keytabs` re-instantiates every realm as
`aes128/aes256-cts-hmac-sha1-96` regardless of how it was created. A realm built with different
etypes silently produces keytabs with the wrong enctype set.

```toml
# src/kerberos/realms/SEA.FUDO.ORG/realm.toml

etypes = ["aes128-cts-hmac-sha1-96", "aes256-cts-hmac-sha1-96"]
max_ticket_lifetime = "1w"
max_renewable_lifetime = "1m"

# Replaces the broken HostConfig.domain -> DomainConfig.realm lookup (REVIEW B4).
# Host membership is then derived from the existing domain-<domain> roles.
domains = ["sea.fudo.org"]

kdc_role = "kdc"
trusts   = ["INFORMIS.LAND", "FUDO.ORG"]

# Principal index — canonical names, not filename-encoded
[principals."postgres/rama.sea.fudo.org"]
kind = "service"
host = "rama"          # belongs to rama; names the hosts a rekey affects

[principals."krbtgt/INFORMIS.LAND@SEA.FUDO.ORG"]
kind = "cross-realm"
peer = "INFORMIS.LAND"

# Named keytabs: an explicit principal list, as opposed to the host keytab's
# implicit "<service>/<fqdn> for the services this host declares".
[keytabs.hermes]
principals = ["hermes/hermes.sea.fudo.org"]
roles      = ["hermes"]   # or hosts = [...]; neither means export-only
```

Note that `host =` on a principal does **not** put it in that host's keytab —
it records ownership, so `rekey-principal` can report which hosts a rotation
affects. A principal reaches a keytab either by being `<service>/<fqdn>` for a
service in `src/hosts/<host>.toml`, or by being named in a `[keytabs]` entry.

This buys three things:

1. **A principal index** — canonical names, queryable, not subject to §1.2's lossy encoding.
2. **Realm/domain binding that works** — resolves `REVIEW B4` without introducing a fourth
   representation of "which hosts are in which realm."
3. **Reproducible instantiation** — `build-keytabs` uses the realm's own etypes instead of a
   hard-coded default.

### 2.2 Resulting tree

```
src/kerberos/realms/<REALM>/
  realm.toml            # NEW — metadata + principal index
  realm.key.age         # realm master key (binary; see REVIEW B3)
  principals/
    <principal>.age     # one decrypted-dump-line per principal, encrypted for admin set
```

---

## 3. Command surface

```bash
# Realms
aegis realm init <REALM> [--etypes ...] [--kdc-role kdc]
aegis realm list                                   # realms, principal counts, member hosts, trusts
aegis realm show <REALM>                           # principals grouped by kind
aegis realm import <REALM> --realm-key ... --principals-dir ...     # exists today

# Principals
aegis realm add-principal <REALM> <principal> [--random-key | --password]
aegis realm remove-principal <REALM> <principal>
aegis realm rekey-principal <REALM> <principal>    # bump kvno, keep old key in keytabs
aegis realm add-service <REALM> <service> --host <host>    # e.g. postgres --host rama

# Cross-realm trust
aegis realm trust <REALM_A> <REALM_B> [--one-way]
aegis realm untrust <REALM_A> <REALM_B>

# Deployment
aegis realm export <REALM>                         # -> build/kdc/<REALM>-principals.age
aegis build-keytabs                                # exists today
```

---

## 4. Implementation notes

In the order I would tackle them.

### 4.1 `realm add-principal` — nearly free

`kdc-add-principal.rb` already exists in `fudo-nix-pkgs/static/` and was **not** vendored into
`aegis-tools-system/scripts/`. Copy it across and wrap it the same way `kerberos.py` wraps the
others. It supports `--password` as well as `--random-key`, which you need for `kadmin/admin`-style
principals.

Vendored today: `initialize-kerberos-realm.rb`, `add-host-to-kerberos-realm.rb`,
`instantiate-kerberos-realm.rb`, `extract-kerberos-host-keytab.rb`, `extract-kerberos-keytab.rb`.

Not vendored, and needed: **`kdc-add-principal.rb`**, **`kdc-merge-principals.rb`**. Optionally
`kdc-convert-database.rb` if you ever change DB backend.

### 4.2 `realm trust` — the payoff from §1.1

```
1. instantiate realm A (existing instantiate_realm)
2. kadmin add --random-key krbtgt/B@A
3. dump --decrypt, extract the krbtgt/B@A line
4. write that identical line, encrypted for the admin set, into BOTH
     src/kerberos/realms/A/principals/
     src/kerberos/realms/B/principals/
5. unless --one-way, repeat with A and B swapped
6. record the peer in both realm.toml [trusts] lists
```

Validate the implementation against the existing `SEA.FUDO.ORG` ↔ `INFORMIS.LAND` pair — that is a
known-good bidirectional trust to diff against.

### 4.3 `realm rekey-principal` — implemented

Kerberos keytabs can hold multiple kvnos, so a graceful rotation is:

1. add a new key at `kvno+1`
2. emit keytabs containing **both** kvnos
3. deploy everywhere
4. drop the old key

Without this, any rotation is a hard cutover in which every service using the principal breaks until
it receives the new keytab simultaneously. This is the difference between "rotation is routine" and
"rotation is an outage," and it is much easier to add now than to retrofit during an incident.

**Implemented.** The mechanism turned out simpler than expected: `kadmin ext_keytab` *appends* to a
keytab rather than truncating it, so no keytab-merging tool is needed. `rekey-principal` archives the
current dump line under `principals/previous/`, rotates the key with `kadmin passwd --random-key`
(via a new `kdc-rekey-principal.rb`), and `build-keytabs` extracts the archived principals from a
second throwaway database into the same keytab file — leaving both kvnos in place. `--prune` drops
the old key once every affected host has been redeployed, and `aegis check` reports principals still
mid-rotation so an unfinished rotation cannot be forgotten.

### 4.4 `realm export` + an `aegis.kdc` NixOS module — the missing half

`build-keytabs` already writes `build/kdc/<REALM>-principals.age`, encrypted for the KDC role
(`aegis/cli.py:613-625`). **Nothing in `aegis/modules/` consumes it** — grepping the module tree for
`kdc` returns only doc-comment mentions. The KDC half of the system does not exist.

The module should:

1. decrypt `<REALM>-principals.age` in **phase 2**, using the KDC role key decrypted in phase 1
2. run `kdc-merge-principals.rb` to build the live database

That script exists precisely for this, and its header states the contract:

> Given an existing KDC database DB and a file containing principals PRINCIPALS, create a new
> database containing the principals in PRINCIPALS, along with any additional principals from DB
> which do not exist in PRINCIPALS. This allows the server to maintain an authoritative list of keys
> for most entities (mostly, hosts) while allowing for the creation and update of users.

That is exactly the right split: the repo is authoritative for host and service principals, while
principals created live on the KDC via `kadmin` (users, one-offs) survive a rebuild. This is the
piece that makes the whole realm story work end to end, and it replaces the `hprop` propagation the
old system used — note the leftover `hprop_nostromo.sea.fudo.org` principal.

---

## 5. Prerequisites

Fix these first, or realm management will be built on sand. All are detailed in
[`REVIEW.md`](./REVIEW.md).

| ID | Blocker | Why it blocks |
|---|---|---|
| **B5** | `pkgs.krb5` → `pkgs.heimdal` in `aegis-tools-system/flake.nix` | Every vendored script uses Heimdal-only commands (`kstash`, `kadmin --local --config-file=`, `dump --decrypt`, `merge`, `dbname = sqlite:`). Nothing Kerberos works until this changes. |
| **B3** | `init-realm` binary handling | Freshly-created realms are unusable; only imported realms work. Route all Kerberos material through one binary-clean path. |
| **B2** | NixOS module must honour `encoding = "base64"` (or the sentinel must go) | Otherwise every deployed keytab is the ASCII string `base64:…` rather than a keytab. |
| **B4** | One representation for host→realm | `build-keytabs` currently finds zero hosts. Recommended: `realm.toml` `domains` + existing `domain-*` roles; delete `DomainConfig` and `HostConfig.domain`. |

---

## 6. Related observations

- **`build-keytabs` skips before it updates the manifest.** `if keytab_output.exists() and not
  force: continue` (`aegis/cli.py:554-557`) fires *before* the manifest write, so a host can end up
  holding a keytab with no manifest entry — and re-running does not repair it. See `REVIEW.md` R5.
- **Principals are encrypted for the admin key alone.** That is consistent with the threat model,
  but it means the admin key protects every Kerberos key in the infrastructure. See `REVIEW.md` R2
  — this is the strongest argument for supporting multiple admin recipients.
- **There is no principal removal or rotation path today.** Adding a host again does not bump kvno;
  `add-host-to-kerberos-realm.rb` skips principals whose files already exist.
