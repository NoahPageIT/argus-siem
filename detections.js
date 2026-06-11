// Argus SIEM - Detection Engine
// Each rule scans the normalized event stream and emits alerts, mapped to MITRE ATT&CK.
// Rules are intentionally readable - this is the part a SOC interviewer will want to see.

const SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// ── helpers ───────────────────────────────────────────────────────────────────
// Service / virtual accounts that fire benign privilege events constantly - filtered to cut alert noise.
const SERVICE_ACCT = /^(sshd_|DWM-|UMFD-|font|IUSR|defaultuser|MSSQL|NT |IIS |Window Manager)/i;
const isGuid = u => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(u || '');
const isSystemAcct = u =>
  !u || /^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON)$/i.test(u)
  || /\$$/.test(u) || SERVICE_ACCT.test(u) || isGuid(u);
const ms = e => new Date(e.ts).getTime();
const within = (a, b, mins) => Math.abs(ms(a) - ms(b)) <= mins * 60000;

// Slide a window over time-sorted events sharing a key; fire when count >= threshold in `mins`.
function burst(events, keyFn, mins, threshold) {
  const groups = {};
  for (const e of events) {
    const k = keyFn(e);
    if (k == null) continue;
    (groups[k] ||= []).push(e);
  }
  const hits = [];
  for (const [key, evs] of Object.entries(groups)) {
    evs.sort((a, b) => ms(a) - ms(b));
    let start = 0;
    for (let end = 0; end < evs.length; end++) {
      while (ms(evs[end]) - ms(evs[start]) > mins * 60000) start++;
      if (end - start + 1 >= threshold) {
        hits.push({ key, window: evs.slice(start, end + 1) });
        break; // one alert per key per scan
      }
    }
  }
  return hits;
}

// ── rules ─────────────────────────────────────────────────────────────────────
const RULES = [
  {
    id: 'brute-force',
    name: 'Brute-force logon attempt',
    severity: 'high',
    mitre: { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
    run(ev) {
      const failed = ev.filter(e => e.eventId === 4625);
      const key = e => (e.sourceIp && e.sourceIp !== '-' ? e.sourceIp : e.workstation || e.user);
      return burst(failed, key, 5, 5).map(h => ({
        title: `Brute force: ${h.window.length} failed logons from "${h.key}"`,
        detail: `${h.window.length} failed logons (event 4625) within 5 minutes targeting account(s) ${[...new Set(h.window.map(e => e.user))].join(', ')}.`,
        entity: h.key, count: h.window.length, events: h.window.map(e => e.id), ts: h.window[h.window.length - 1].ts,
      }));
    },
  },
  {
    id: 'success-after-failures',
    name: 'Successful logon after repeated failures',
    severity: 'critical',
    mitre: { id: 'T1110', name: 'Brute Force → Valid Accounts', tactic: 'Credential Access' },
    run(ev) {
      const alerts = [];
      const success = ev.filter(e => e.eventId === 4624 && !isSystemAcct(e.user));
      const failed = ev.filter(e => e.eventId === 4625);
      for (const s of success) {
        const priorFails = failed.filter(f => f.user === s.user && ms(f) < ms(s) && within(f, s, 10));
        if (priorFails.length >= 3) {
          alerts.push({
            title: `Possible cracked credential: "${s.user}" logged in after ${priorFails.length} failures`,
            detail: `Account "${s.user}" had ${priorFails.length} failed logons in the 10 minutes before a successful logon (4624). Classic brute-force success pattern.`,
            entity: s.user, count: priorFails.length, events: [...priorFails.map(e => e.id), s.id], ts: s.ts,
          });
        }
      }
      return alerts;
    },
  },
  {
    id: 'account-lockout',
    name: 'Account lockout',
    severity: 'medium',
    mitre: { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
    run(ev) {
      return ev.filter(e => e.eventId === 4740).map(e => ({
        title: `Account locked out: "${e.user}"`,
        detail: `Account "${e.user}" was locked out (event 4740) - often the tail end of a brute-force attempt.`,
        entity: e.user, count: 1, events: [e.id], ts: e.ts,
      }));
    },
  },
  {
    id: 'new-account',
    name: 'New user account created',
    severity: 'medium',
    mitre: { id: 'T1136.001', name: 'Create Account: Local Account', tactic: 'Persistence' },
    run(ev) {
      return ev.filter(e => e.eventId === 4720).map(e => ({
        title: `New account created: "${e.user}"`,
        detail: `A new user account "${e.user}" was created (event 4720) by ${e.subject || 'unknown'}. Attackers create accounts for persistence.`,
        entity: e.user, count: 1, events: [e.id], ts: e.ts,
      }));
    },
  },
  {
    id: 'priv-assigned',
    name: 'Privileged logon (admin rights assigned)',
    severity: 'low',
    mitre: { id: 'T1078.003', name: 'Valid Accounts: Local Accounts', tactic: 'Privilege Escalation' },
    run(ev) {
      // 4672 fires constantly for SYSTEM/service accounts - surface only real (human) accounts,
      // and aggregate per account so we get one tuned alert instead of dozens of duplicates.
      const real = ev.filter(e => e.eventId === 4672 && !isSystemAcct(e.subject));
      const byUser = {};
      for (const e of real) (byUser[e.subject] ||= []).push(e);
      return Object.entries(byUser).map(([u, evs]) => ({
        title: `Privileged session: "${u}" (${evs.length}× admin rights)`,
        detail: `Administrative privileges assigned to "${u}" ${evs.length} time(s) (event 4672). Expected for the device owner; flagged for any unexpected account.`,
        entity: u, count: evs.length, events: evs.map(e => e.id), ts: evs[evs.length - 1].ts,
      }));
    },
  },
  {
    id: 'audit-cleared',
    name: 'Security audit log cleared',
    severity: 'critical',
    mitre: { id: 'T1070.001', name: 'Indicator Removal: Clear Windows Event Logs', tactic: 'Defense Evasion' },
    run(ev) {
      return ev.filter(e => e.eventId === 1102).map(e => ({
        title: `Security log was cleared`,
        detail: `The Security event log was cleared (event 1102) by ${e.subject || 'unknown'}. Strong anti-forensics / cover-tracks signal.`,
        entity: e.subject || e.computer, count: 1, events: [e.id], ts: e.ts,
      }));
    },
  },
  {
    id: 'off-hours-logon',
    name: 'Off-hours interactive logon',
    severity: 'low',
    mitre: { id: 'T1078', name: 'Valid Accounts', tactic: 'Initial Access' },
    run(ev) {
      // interactive (2) or remote-interactive/RDP (10) logon between 02:00-06:00 local - aggregated per user
      const hits = ev.filter(e => {
        if (e.eventId !== 4624 || isSystemAcct(e.user)) return false;
        if (!['2', '10'].includes(String(e.logonType))) return false;
        const h = new Date(e.ts).getHours();
        return h >= 2 && h < 6;
      });
      const byUser = {};
      for (const e of hits) (byUser[e.user] ||= []).push(e);
      return Object.entries(byUser).map(([u, evs]) => ({
        title: `Off-hours logon: "${u}" (${evs.length}×, 02:00-06:00)`,
        detail: `${evs.length} interactive logon(s) for "${u}" during off-hours. RDP/console access at unusual times warrants a glance.`,
        entity: u, count: evs.length, events: evs.map(e => e.id), ts: evs[evs.length - 1].ts,
      }));
    },
  },
];

// Run every rule over the events, return a flat, severity-sorted alert list.
function detect(events) {
  const alerts = [];
  for (const rule of RULES) {
    let found = [];
    try { found = rule.run(events) || []; } catch (e) { /* a bad rule shouldn't kill the scan */ }
    for (const a of found) {
      alerts.push({ ...a, ruleId: rule.id, ruleName: rule.name, severity: rule.severity, mitre: rule.mitre });
    }
  }
  alerts.sort((a, b) => (SEV[b.severity] - SEV[a.severity]) || (new Date(b.ts) - new Date(a.ts)));
  return alerts;
}

module.exports = { RULES, detect, SEV };
