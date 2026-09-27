# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues, pull
requests, or discussions.**

Instead, report privately through either channel:

- Email **security@getbusbar.com**, or
- GitHub's [private vulnerability reporting](https://github.com/GetBusbar/busbar-store-sqlite/security/advisories/new)
  (the **Security** tab on this repository).

Please include:

- A description of the issue and its potential impact.
- Steps to reproduce (proof-of-concept if available).
- Affected version / commit.
- Any suggested mitigation.

We aim to **acknowledge your report within 48 hours**, work with you on a fix, and
coordinate disclosure timing. Confirmed vulnerabilities are published as
[GitHub Security Advisories](https://github.com/GetBusbar/busbar-store-sqlite/security/advisories),
through which we request and issue **CVE** identifiers. We credit reporters who wish to be
credited once a fix is released.

## Scope

`store-sqlite` is a `kind: store` busbar plugin: it persists busbar's governance
data — virtual keys, usage ledgers, and the durable audit log — to a local SQLite
file. Issues of particular interest include:

- SQL injection or any path where request-derived data reaches a query
  unparameterized.
- Corruption or loss of virtual-key, budget, or audit data across a crash or a
  concurrent-access race (`rusqlite::Connection` is mutex-guarded; a bypass of
  that guard is in scope).
- A load-time config error (e.g. a malformed `db_path`) surfacing as a silent
  success instead of a clean `Err` across the plugin ABI.
- Path handling around `db_path` that could let a config value escape the
  intended directory (e.g. traversal) in a deployment that derives it from
  untrusted input.

See busbar's own [threat model](https://github.com/GetBusbar/busbar/blob/main/THREAT_MODEL.md)
for the trust boundaries this plugin operates inside.

## Supported versions

This plugin is versioned independently of busbar (see the README's
[Versioning](README.md#versioning) section). Security fixes are applied to the
latest `main` and the most recent tagged release of **this repository**. Pin to a
tag for production use.
