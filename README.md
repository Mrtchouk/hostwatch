# hostwatch

Intrusion and drift detection for a single Linux server, in bash. It scans, it
decides whether what it found matters, it fixes what it can fix without
interrupting anything, and it asks before touching what would.

Everything runs locally. No agent, no daemon, no account, nothing leaves the
machine. Debian and Ubuntu, root, `jq` and `curl`.

```
$ hostwatch
web01 - 2026-08-27 22:00:03 - ACTION

2 critical item(s) to fix, 3 warning(s).

CRIT Secret file readable by everyone
     /var/www/app/.env (mode 644) - chmod 640
CRIT Public listening ports changed (added)
     ADDED:
     0.0.0.0:9000
WARN Certificate app.example.com expires in 9 days
WARN 4 security update(s) pending
WARN 1284 requests against sensitive paths

Fixed automatically
  + Secret file permissions tightened to 640
  + Security patches applied, service packages excluded

Waiting for your decision
  ? Upgrade service packages: nginx libnginx-mod-http-geoip (hostwatch approve p1756-24193)
     Installing these restarts the web server. Everything it serves is down for the duration.

Priorities
  Public listening ports changed (added)
     A new public listener is either a deployment or something that installed itself.
     $ ss -tlnp

Ignored: 1284 requests against sensitive paths - Automated scanning is constant
background traffic on any public address.
```

## Why this exists

I run one server. It hosts game servers, a panel, a dashboard and a database,
and I am the only person who looks after it. Everything I tried was built for
somebody else: hosted agents that want an account and ship your logs to a third
party, or full SIEM stacks that need more attention than the box they watch.

The alternative most people fall back on is a cron job mailing them the output
of a few commands. That works for about a week. Then the noise wins: the
internet scans every public address constantly, so a daily digest is mostly
failed SSH attempts and probes for /wp-login, and you stop reading it. The day
something real shows up, it is in there, unread, on line 400.

So the useful part was never collecting the data. It was deciding what deserves
your attention, and repairing the small things without asking. That is what this
does.

## What it looks for

Two blocks. The intrusion block is cheap and runs on a five-minute timer; the
full sweep runs five times a day.

Access and persistence — SSH keys, UID 0 accounts, successful logins from
addresses never seen before, `ld.so.preload`, miners and reverse shells in the
process table, new SUID binaries, changes to sshd, sudoers, cron and nginx.

Exposure — public listeners, firewall rules, database accounts reachable from
outside, world-readable secrets, archives and `.git` directories under a
document root, endpoints that must never answer 200, recently written PHP
calling `eval` or `shell_exec`.

Operations — certificate expiry, a broken ACME account (which fails renewal
silently until the certificate dies), disk and inodes, pending security
updates, kernel reboot flag, services and PM2 processes that are down.

Full list with codes: [docs/checks.md](docs/checks.md).

## How it avoids crying wolf

Most of this is drift detection against a baseline learned on first run. The
part that makes it usable daily is that added and removed are not the same
event. A key appearing in `authorized_keys` is a backdoor; a key disappearing is
housekeeping. A port opening is suspicious; a port closing is a service someone
stopped. Score both as critical and you get an alert every time you restart
anything, and within a week nobody reads the channel.

A baseline also absorbs the change once it has reported it. One drift, one
alert, not one per cycle forever.

The rule engine (`hostwatch-triage`) then sorts findings into signal and noise.
Failed SSH bruteforce, scans for `/wp-login` and `/.env`, fail2ban ban counts:
background radiation on any public address, reported as metrics, never as
events. A successful login from an unknown address is the opposite.

## Fixing things

`hostwatch-fix` is a strict allowlist of action keys. Not commands — keys:
`perm_env`, `db_block`, `certbot_renew`, `svc_start:<name>`, `apt_security_safe`.
Nothing upstream can express anything else. That is the entire security model
for automatic remediation, and it is why an unprivileged process is allowed to
trigger one at all.

Actions split in two:

- **interrupt nothing** — applied immediately, no question asked. Tightening
  permissions on a secret file, restoring a firewall rule, starting a service
  that is already down, patching packages that do not restart a daemon.
- **interrupt something** — never automatic. Queued, reported, and executed only
  after an explicit decision: now, at a chosen time, or never.

```bash
hostwatch pending
hostwatch approve p1756-24193 now
hostwatch approve p1756-24193 $(date -d 03:00 +%s)
hostwatch approve p1756-24193 refuse
```

Set `HW_AUTOFIX=0` if you want it to report and never touch anything.

## Install

```bash
git clone https://github.com/Mrtchouk/hostwatch
cd hostwatch
sudo ./install.sh
sudo nano /etc/hostwatch/hostwatch.conf
sudo hostwatch now
```

The installer copies to `/opt/hostwatch`, writes the config, enables three
systemd units and seeds the baselines. **The first run records the current state
as trusted.** Install on a host you believe is clean, or you are teaching it that
the backdoor belongs there.

Configure at minimum: `HW_SERVICES`, `HW_SECRET_FILES`, `HW_WEBROOTS`,
`HW_SITES`. Everything is a bash array in one file.

## Reporting

Reports are JSON on disk, in `/var/lib/hostwatch/reports`. Three ways to read
them:

- `hostwatch` in a terminal.
- A webhook. Set `HW_WEBHOOK_FILE` and `HW_WEBHOOK_MODE=always`. Works with
  Discord and Slack, no bot required.
- The [Discord bot](integrations/discord-bot), which adds on-demand scans and
  approval buttons. It runs unprivileged and cannot make the host execute
  anything outside the allowlist.

## Files

```
/etc/hostwatch/hostwatch.conf     configuration
/var/lib/hostwatch/baseline/      learned reference state
/var/lib/hostwatch/scans/         last 60 raw scans
/var/lib/hostwatch/reports/       last 80 full reports
/var/lib/hostwatch/pending/       actions awaiting a decision
/var/lib/hostwatch/outbox/        reports not yet published
/var/spool/hostwatch/requests/    inbound requests from unprivileged consumers
/var/log/hostwatch.log            plain text log
```

## Cost

A full scan is about 3 seconds on a small VPS, dominated by the SUID sweep and
HTTP probes, which run in parallel. The five-minute pass is around 0.1 second.
Timers are `Nice=10` with idle IO scheduling.

## Known limitations

- Baseline drift detects change, not intent. It tells you a SUID binary appeared;
  deciding whether that was your package manager is your job.
- Everything is local. A root-level compromise can rewrite the baselines. This
  is a tripwire for a single host, not a substitute for shipping logs off it.
- The webshell check greps recently modified PHP for execution primitives. It
  catches lazy shells, not obfuscated ones.
- Container internals are out of scope. Image layers are pruned from the SUID
  sweep because they churn constantly and are not executable from the host.
- Debian and Ubuntu. The apt checks and `/var/run/reboot-required` are
  Debian-specific; the rest is portable but untested elsewhere.

## Licence

MIT.
