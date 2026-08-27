// Publishes hostwatch reports to a Discord channel and carries approval
// decisions back.
//
// The bot holds no privilege. It reads reports from $HW_LIB and writes request
// files into $HW_SPOOL; a root-side systemd path unit picks those up and runs
// a fixed action. A compromised bot cannot make the host run anything that is
// not already in the hostwatch-fix allowlist.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  Client, GatewayIntentBits, EmbedBuilder, ButtonBuilder, ButtonStyle,
  ActionRowBuilder, StringSelectMenuBuilder, PermissionFlagsBits,
  SlashCommandBuilder, REST, Routes, MessageFlags,
} = require('discord.js');

const LIB = process.env.HW_LIB || '/var/lib/hostwatch';
const SPOOL = process.env.HW_SPOOL || '/var/spool/hostwatch/requests';
const CHANNEL = process.env.HW_DISCORD_CHANNEL;
const PING_ROLE = process.env.HW_DISCORD_PING_ROLE || '';
const POLL_MS = Number(process.env.HW_DISCORD_POLL_MS || 20000);

const OUTBOX = path.join(LIB, 'outbox');
const REPLIES = path.join(LIB, 'replies');
const REPORTS = path.join(LIB, 'reports');
const PENDING = path.join(LIB, 'pending');

const VERDICT = {
  ok:     { label: 'CLEAR',    color: 0x3ba55d },
  watch:  { label: 'WATCH',    color: 0xfaa61a },
  action: { label: 'ACTION',   color: 0xe67e22 },
  urgent: { label: 'URGENT',   color: 0xed4245 },
};
const KIND = {
  periodic: 'Security report',
  alert: 'Security alert',
  manual: 'On-demand scan',
  fix: 'Remediation',
};

const SLOTS = [
  { key: 'h1', label: 'In one hour', hours: 1 },
  { key: 'h23', label: 'Tonight, 23:00', at: 23 },
  { key: 'h03', label: 'Tonight, 03:00', at: 3 },
  { key: 'h05', label: 'Tonight, 05:00', at: 5 },
  { key: 'h07', label: 'Tomorrow, 07:00', at: 7 },
];

const slotEpoch = (slot) => {
  const d = new Date();
  if (slot.hours) return Math.floor((d.getTime() + slot.hours * 3600000) / 1000);
  d.setHours(slot.at, 0, 0, 0);
  if (d.getTime() <= Date.now()) d.setDate(d.getDate() + 1);
  return Math.floor(d.getTime() / 1000);
};

const readJSON = (f) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } };
const cut = (s, n) => { const t = String(s || '').replace(/\r/g, '').trim(); return t.length > n ? t.slice(0, n - 1) + '…' : t; };
const listJSON = (dir) => { try { return fs.readdirSync(dir).filter(f => f.endsWith('.json')).sort(); } catch { return []; } };

const latestReport = () => {
  const f = listJSON(REPORTS).pop();
  return f ? readJSON(path.join(REPORTS, f)) : null;
};

// Ask the root side for a fresh scan and wait for the answer file.
function requestScan(userId, timeoutMs = 300000) {
  const id = `${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
  const tmp = path.join(SPOOL, `.${id}.tmp`);
  // Atomic rename: the path unit must never read a half-written request.
  fs.writeFileSync(tmp, JSON.stringify({ id, user: String(userId || ''), kind: 'manual' }));
  fs.renameSync(tmp, path.join(SPOOL, `${id}.json`));

  const reply = path.join(REPLIES, `${id}.json`);
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tick = () => {
      const data = readJSON(reply);
      if (data) return resolve(data);
      if (Date.now() > deadline) return reject(new Error('timeout'));
      setTimeout(tick, 2500);
    };
    setTimeout(tick, 3000);
  });
}

function sendDecision(pendingId, when, userId) {
  const id = `${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;
  const tmp = path.join(SPOOL, `.${id}.tmp`);
  fs.writeFileSync(tmp, JSON.stringify({
    id, kind: 'approve', pending: pendingId, when: String(when), user: String(userId || ''),
  }));
  fs.renameSync(tmp, path.join(SPOOL, `${id}.json`));
}

function buildReport(report, { compact = false } = {}) {
  const a = report.analysis || {};
  const scan = report.scan || {};
  const counts = scan.counts || { crit: 0, warn: 0, info: 0 };
  const m = scan.metrics || {};
  const v = VERDICT[a.verdict] || VERDICT.watch;

  const crit = (scan.findings || []).filter(f => f.level === 'crit');
  const warn = (scan.findings || []).filter(f => f.level === 'warn');
  const waiting = (report.pending || []).filter(p => p.status === 'waiting');
  const scheduled = (report.pending || []).filter(p => p.status === 'scheduled');
  const fixed = (report.autofix?.done || []).filter(f => f.ok);

  const embed = new EmbedBuilder()
    .setColor(v.color)
    .setTitle(`${KIND[report.kind] || KIND.periodic} — ${v.label}`)
    .setDescription(cut(a.summary, 600) || 'No summary.')
    .setFooter({ text: `${scan.host || 'host'} · ${scan.mode || '?'} scan in ${scan.duration_s || '?'}s` })
    .setTimestamp();

  const lines = [
    ...crit.slice(0, compact ? 3 : 6).map(f => `\`CRIT\` **${cut(f.title, 90)}**\n-# ${cut(f.detail, 180).replace(/\n/g, ' · ')}`),
    ...warn.slice(0, compact ? 2 : 5).map(f => `\`WARN\` ${cut(f.title, 90)}`),
  ];
  embed.addFields({
    name: `Findings — ${counts.crit} critical, ${counts.warn} warnings`,
    value: cut(lines.join('\n') || 'Nothing anomalous this cycle.', 1024),
  });

  const prio = (a.priorities || []).slice(0, compact ? 2 : 3);
  if (prio.length) {
    embed.addFields({
      name: 'What to do',
      value: cut(prio.map((p, i) => `**${i + 1}. ${cut(p.title, 80)}**\n-# ${cut(p.why, 160)}`
        + (p.command ? `\n\`\`\`bash\n${cut(p.command, 200)}\n\`\`\`` : '')).join('\n'), 1024),
    });
  }
  if (fixed.length) {
    embed.addFields({
      name: 'Fixed automatically',
      value: cut(fixed.map(f => `✓ ${cut(f.label, 90)}`).join('\n'), 1024),
    });
  }
  if (waiting.length || scheduled.length) {
    embed.addFields({
      name: 'Needs your approval (this interrupts service)',
      value: cut([
        ...waiting.map(p => `**${cut(p.label, 100)}**\n-# ${cut(p.why, 180)}`),
        ...scheduled.map(p => `${cut(p.label, 90)} — scheduled <t:${p.run_at}:R>`),
      ].join('\n'), 1024),
    });
  }
  if (!compact && a.analysis) {
    embed.addFields({ name: 'Analysis', value: cut(a.analysis, 1024) });
  }
  embed.addFields({
    name: 'Host',
    value: cut([
      `SSH 24h: ${m.ssh_failed_24h || 0} failed`,
      `fail2ban: ${m.fail2ban_banned || 0} banned`,
      `HTTP probes: ${m.http_scan_hits || 0}`,
      `${m.disk || '?'} · load ${m.load || '?'}`,
    ].join(' · '), 1024),
  });

  const rows = waiting.slice(0, 2).map(p => new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId(`hwfix:${p.id}:now`).setLabel('Apply now').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId(`hwfix:${p.id}:later`).setLabel('Schedule').setStyle(ButtonStyle.Secondary),
    new ButtonBuilder().setCustomId(`hwfix:${p.id}:no`).setLabel('Not now').setStyle(ButtonStyle.Secondary),
  ));

  return { embeds: [embed], components: rows };
}

function buildFixNotice(report) {
  const f = report.fix || {};
  const map = {
    done: { color: 0x3ba55d, txt: 'applied' },
    failed: { color: 0xed4245, txt: 'failed' },
    scheduled: { color: 0xfaa61a, txt: 'scheduled' },
    refused: { color: 0x99aab5, txt: 'dismissed' },
    starting: { color: 0xed4245, txt: 'starting' },
  }[f.status] || { color: 0x5865f2, txt: f.status };

  return {
    embeds: [new EmbedBuilder()
      .setColor(map.color)
      .setTitle(`${KIND.fix} — ${map.txt}`)
      .setDescription(cut(f.label, 300))
      .addFields({ name: 'Result', value: cut(f.result, 1024) || '—' })
      .setFooter({ text: report.requester ? `decided by ${report.requester}` : 'automatic' })
      .setTimestamp()],
  };
}

function pingReason(report) {
  if (report.kind === 'fix') {
    if (report.fix?.status === 'failed') return 'a remediation failed';
    if (report.fix?.status === 'starting') return 'reboot imminent';
    return null;
  }
  const crit = report.scan?.counts?.crit || 0;
  const waiting = (report.pending || []).filter(p => p.status === 'waiting').length;
  if (crit > 0) return `${crit} critical finding(s)`;
  if (waiting > 0) return 'an action needs approval (it interrupts service)';
  if (report.analysis?.verdict === 'urgent') return 'urgent verdict';
  if (report.analysis?.verdict === 'action') return 'a fix is needed';
  return null;
}

const posted = new Set();

async function flushOutbox(client) {
  const files = listJSON(OUTBOX);
  if (!files.length) return;
  const channel = await client.channels.fetch(CHANNEL).catch(() => null);

  // After a long outage, do not dump forty reports into the channel.
  for (const f of files.slice(0, Math.max(0, files.length - 5))) {
    try { fs.unlinkSync(path.join(OUTBOX, f)); } catch {}
  }

  for (const f of files.slice(-5)) {
    const full = path.join(OUTBOX, f);
    if (posted.has(f)) { try { fs.unlinkSync(full); } catch {} continue; }
    const report = readJSON(full);
    if (!report) { try { fs.unlinkSync(full); } catch {} continue; }

    if (channel) {
      try {
        const payload = report.kind === 'fix'
          ? buildFixNotice(report)
          : buildReport(report, { compact: report.kind === 'alert' });
        await channel.send({ ...payload, allowedMentions: { parse: [] } });

        const reason = pingReason(report);
        if (reason && PING_ROLE) {
          await channel.send({
            content: `<@&${PING_ROLE}> — ${reason}. Details above.`,
            allowedMentions: { parse: ['roles'] },
          }).catch(() => {});
        }
      } catch (e) {
        console.error('[hostwatch] send failed:', e.message);
        return;   // keep the file, retry next tick
      }
    }
    posted.add(f);
    if (posted.size > 200) posted.clear();
    try { fs.unlinkSync(full); } catch {}
  }
}

const command = new SlashCommandBuilder()
  .setName('hostwatch')
  .setDescription('Server security')
  .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
  .addSubcommand(s => s.setName('report').setDescription('Run a scan now and post the result'))
  .addSubcommand(s => s.setName('last').setDescription('Show the most recent report'))
  .addSubcommand(s => s.setName('pending').setDescription('Actions waiting for a decision'));

async function onInteraction(interaction) {
  if (interaction.isChatInputCommand() && interaction.commandName === 'hostwatch') {
    const sub = interaction.options.getSubcommand();

    if (sub === 'last') {
      const r = latestReport();
      if (!r) return interaction.reply({ content: 'No report yet.', flags: MessageFlags.Ephemeral });
      return interaction.reply(buildReport(r));
    }

    if (sub === 'pending') {
      const items = listJSON(PENDING).map(f => readJSON(path.join(PENDING, f))).filter(Boolean)
        .filter(p => p.status === 'waiting' || p.status === 'scheduled');
      if (!items.length) return interaction.reply({ content: 'Nothing waiting.', flags: MessageFlags.Ephemeral });
      return interaction.reply({
        content: items.map(p => `\`${p.id}\` ${p.status} — ${cut(p.label, 120)}`).join('\n'),
        flags: MessageFlags.Ephemeral,
      });
    }

    await interaction.deferReply();
    try {
      const report = await requestScan(interaction.user.id);
      return interaction.editReply(buildReport(report));
    } catch {
      return interaction.editReply('The scan did not answer in time. The root side may be down.');
    }
  }

  const isBtn = interaction.isButton() && interaction.customId.startsWith('hwfix:');
  const isSel = interaction.isStringSelectMenu() && interaction.customId.startsWith('hwtime:');
  if (!isBtn && !isSel) return;

  // Interrupting production is not a passer-by's click.
  if (!interaction.memberPermissions?.has(PermissionFlagsBits.Administrator)) {
    return interaction.reply({ content: 'Administrator only.', flags: MessageFlags.Ephemeral });
  }

  const pendingId = interaction.customId.split(':')[1];
  const p = readJSON(path.join(PENDING, `${pendingId}.json`));
  if (!p) return interaction.reply({ content: 'That action no longer exists.', flags: MessageFlags.Ephemeral });
  if (p.status !== 'waiting' && !(isSel && p.status === 'scheduled')) {
    return interaction.reply({ content: `Already handled (${p.status}).`, flags: MessageFlags.Ephemeral });
  }

  if (isSel) {
    const slot = SLOTS.find(s => s.key === interaction.values[0]);
    if (!slot) return;
    const when = slotEpoch(slot);
    sendDecision(pendingId, when, interaction.user.id);
    return interaction.update({ content: `**${p.label}** scheduled for <t:${when}:F>.`, components: [] });
  }

  const choice = interaction.customId.split(':')[2];
  if (choice === 'later') {
    const menu = new StringSelectMenuBuilder()
      .setCustomId(`hwtime:${pendingId}`)
      .setPlaceholder('When?')
      .addOptions(SLOTS.map(s => ({ label: s.label, value: s.key })));
    return interaction.reply({
      content: `**${p.label}**\nWhen should this run?`,
      components: [new ActionRowBuilder().addComponents(menu)],
      flags: MessageFlags.Ephemeral,
    });
  }

  sendDecision(pendingId, choice === 'now' ? 'now' : 'refuse', interaction.user.id);
  return interaction.reply({
    content: choice === 'now'
      ? `**${p.label}** started. The result lands in this channel.`
      : `**${p.label}** dismissed. It will be raised again if things get worse.`,
    flags: MessageFlags.Ephemeral,
  });
}

async function main() {
  for (const [k, v] of Object.entries({ HW_DISCORD_TOKEN: process.env.HW_DISCORD_TOKEN, HW_DISCORD_CHANNEL: CHANNEL })) {
    if (!v) { console.error(`${k} is not set`); process.exit(1); }
  }
  if (!fs.existsSync(OUTBOX)) {
    console.error(`${OUTBOX} does not exist. Install hostwatch on this host first.`);
    process.exit(1);
  }

  const client = new Client({ intents: [GatewayIntentBits.Guilds] });
  client.on('interactionCreate', i => onInteraction(i).catch(e => console.error('[hostwatch]', e.message)));

  client.once('clientReady', async () => {
    console.log(`[hostwatch] connected as ${client.user.tag}`);
    const rest = new REST().setToken(process.env.HW_DISCORD_TOKEN);
    await rest.put(Routes.applicationCommands(client.user.id), { body: [command.toJSON()] })
      .catch(e => console.error('[hostwatch] command registration failed:', e.message));
    const tick = () => flushOutbox(client).catch(e => console.error('[hostwatch]', e.message));
    setInterval(tick, POLL_MS);
    tick();
  });

  await client.login(process.env.HW_DISCORD_TOKEN);
}

main();
