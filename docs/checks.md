# Checks

`fast` runs block A only, on the five-minute timer. `full` runs everything.

Findings carry a stable `code`. Drift findings also emit `<code>.rm` when
something disappeared instead of appearing, usually at a lower level.

## Block A — access, persistence, compromise

| Code | Level | What it means |
|---|---|---|
| `sshkeys.drift` | crit | A key was added to an `authorized_keys` file. Removals are info. |
| `accounts.drift` | crit | New UID 0 account, passwordless account, or a changed login shell. Removals are warn. |
| `sshlogin.newip` | crit | A successful SSH login from a source address never seen before. |
| `rootkit.preload` | crit | `/etc/ld.so.preload` is not empty. A library is injected into every process. |
| `proc.suspect` | crit | Known miner names, binaries running from `/tmp` or `/dev/shm`, listening netcat, `bash -i >& /dev/tcp`. |
| `ports.drift` | warn | A new public listener appeared. Closures are info. |
| `service.down` | crit | A service listed in `HW_SERVICES` is not active. |
| `service.pm2` | crit | A PM2 process listed in `HW_PM2_APPS` is not online. |
| `webshell.suspect` | crit | A PHP file modified in the last two days calls `eval`, `shell_exec`, `passthru` or `base64_decode`. |
| `config.drift` | warn | A hash changed in sshd, sudoers, passwd, group, hosts, crontab, nginx sites or `cron.d`. |

## Block B — exposure and operations

| Code | Level | What it means |
|---|---|---|
| `ssl.expired` | crit | A Let's Encrypt certificate is past its end date. |
| `ssl.soon` | warn | Under 14 days left. |
| `ssl.unreadable` | warn | The certificate could not be parsed. |
| `certbot.account` | warn | The ACME log shows an account error. Renewal fails silently in this state. |
| `secret.worldread` | crit | A file in `HW_SECRET_FILES` is world-readable. |
| `db.super` | crit | A database account on host `%` or `0.0.0.0` holds SUPER. |
| `db.rootremote` | crit | Database `root` accepts connections from outside the host. |
| `db.noblock` | warn | No firewall rule dropping external traffic on the database port. |
| `fw.drift` | warn | iptables rules changed, excluding Docker and fail2ban chains. |
| `suid.drift` | crit | A SUID or SGID binary appeared. Removals are info. |
| `cron.drift` | warn | A cron entry or systemd timer changed. |
| `disk.full` | crit | Root filesystem at or above `HW_DISK_CRIT`. |
| `disk.high` | warn | At or above `HW_DISK_WARN`. |
| `disk.inodes` | warn | Inode usage at or above `HW_INODE_WARN`. |
| `webroot.sensitive` | warn | `.env`, `.git`, a SQL dump or an archive sits under a document root. |
| `f2b.spike` | warn | More than `HW_F2B_SPIKE` IPs currently banned. Classified as noise by the rule engine. |
| `apt.security` | warn | Security updates pending. |
| `kernel.reboot` | warn | `/var/run/reboot-required` exists. |
| `http.scan` | warn | More than `HW_HTTP_SCAN_SPIKE` requests against sensitive paths. Noise. |
| `http.leak` | crit | One of those paths answered 200. Something was served. |
| `docker.drift` | warn | A container's `0.0.0.0` port publications changed. |
| `site.down` | warn | A URL in `HW_SITES` did not answer 2xx or 3xx. |
| `url.exposed` | crit | A URL in `HW_URLS_FORBIDDEN` answered 200. |
| `baseline.<name>` | info | First run for that baseline. Reference state recorded, never an alert. |

## Metrics

Always present in `metrics`, reported but never scored: uptime, load, disk, memory,
SSH accepted and failed counts over 24h, new source IPs, fail2ban ban count,
remote database connections, HTTP probe volume and top sources, PM2 restart counts.

## Adding a check

Add it to `bin/hostwatch-scan` in the right block, `emit` a level, a code, a
title and a detail. Add the code to `share/rules.json` so the rule engine knows
why it matters and what command investigates it. Nothing else needs to change:
the report, the CLI, the webhook and the Discord bot all read the contract.
