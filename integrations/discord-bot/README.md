# Discord integration

Optional. hostwatch works with a plain webhook (`HW_WEBHOOK_MODE=always`); this
bot exists for the parts a webhook cannot do: run a scan on demand, and approve
an action that takes services down.

## Why a spool instead of sudo

The scan needs root: iptables, `/etc/shadow`, SUID sweeps, certificate files.
Giving the bot sudo means anyone who compromises the bot owns the host. So the
relationship is inverted. The bot writes a request file:

```json
{ "id": "abc123", "user": "42", "kind": "approve", "pending": "p1712-9931", "when": "now" }
```

A systemd path unit notices it and runs `hostwatch-agent` as root. The request
names an action **already queued by the scan**, never a command. Every field is
filtered character by character. The worst a hostile request achieves is a scan
it was allowed to ask for anyway, six times per ten minutes.

## Install

Run it as an unprivileged user on the same host.

```bash
cd integrations/discord-bot
npm install
cp .env.example .env      # fill in token and channel
node hostwatch-discord.js
```

The bot needs read access to `/var/lib/hostwatch` and write access to the
request spool and the outbox. Give it a group:

```bash
groupadd -f hostwatch
usermod -aG hostwatch botuser
chgrp hostwatch /var/spool/hostwatch/requests /var/lib/hostwatch/outbox
chmod 2775 /var/spool/hostwatch/requests /var/lib/hostwatch/outbox
```

Then set `HW_OUTBOX_GROUP=hostwatch` in `hostwatch.conf`, so the report writer
keeps those permissions on every run.

The outbox has to stay group-writable: the bot deletes each report after
posting it. Reset it to 755 and reports pile up silently forever.

## Commands

- `/hostwatch report` — scan and analyse now, answer in channel
- `/hostwatch last` — most recent report, no scan
- `/hostwatch pending` — actions waiting for a decision

Reports carrying a disruptive action show three buttons: apply now, schedule
(five slots), dismiss. Administrator permission required, checked on the
interaction, not on the message.

## Running it under a process manager

```bash
pm2 start hostwatch-discord.js --name hostwatch-discord
pm2 save
```
