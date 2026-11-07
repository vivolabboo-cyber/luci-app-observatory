"""Bounded passive device diagnostics. No probes, payloads or route changes."""
import collections
import ipaddress
import json
import os
import pathlib
import re
import time

MAX_ROWS = 1500
RETENTION = 7200

class Diagnostics:
    def __init__(self, runtime):
        self.path = pathlib.Path(runtime) / 'diagnostics.json'
        self.started = int(time.time())
        self.rows = collections.OrderedDict()
        self.pending = {}
        self.flows = {}
        self.sequence = 0
        self.dropped = 0

    def record(self, key, row):
        if key not in self.rows:
            while len(self.rows) >= MAX_ROWS:
                self.rows.popitem(last=False)
                self.dropped += 1
        self.rows[key] = row
        self.rows.move_to_end(key)

    def dns(self, line, now, ip_device):
        prefix = re.search(r'dnsmasq(?:\[\d+\])?:\s+(\d+)\s+', line)
        if not prefix:
            return
        ident = prefix[1]
        query = re.search(r'query\[([^]]+)\]\s+(\S+)\s+from\s+(\S+)', line)
        if query:
            dev = ip_device.get(query[3])
            domain = query[2].lower().rstrip('.')
            if not dev or len(domain) > 253 or not re.fullmatch(r'[a-z0-9_.-]+', domain):
                return
            self.sequence += 1
            key = 'dns:' + str(self.sequence)
            self.record(key, dict(kind='dns', device=dev, domain=domain, first=now,
                last=now, status='dns_pending', route='unknown', source='dnsmasq',
                protocol=query[1][:16], up=None, down=None, evidence=''))
            self.pending[ident] = key
            while len(self.pending) > 3000:
                self.pending.pop(next(iter(self.pending)))
            return
        key = self.pending.get(ident)
        row = self.rows.get(key)
        if not row or now - row['first'] > 30:
            return
        answer = re.search(r'(?:reply|cached(?:-stale)?|config)\s+(\S+)\s+is\s+(\S+)', line)
        failure = re.search(r'(?:reply\s+error\s+is\s+|\bis\s+)(SERVFAIL|REFUSED|NXDOMAIN)\b', line)
        if not answer and not failure:
            return
        if answer and answer[1].lower().rstrip('.') != row['domain']:
            return
        value = failure[1] if failure else answer[2]
        if value in ('0.0.0.0', '::'):
            status = 'dns_sinkhole'
        elif value in ('SERVFAIL', 'REFUSED'):
            status = 'dns_error'
        elif value == 'NXDOMAIN':
            status = 'dns_nxdomain'
        elif value.startswith('NODATA'):
            status = 'dns_nodata'
        elif value == '<CNAME>':
            status = 'dns_cname'
        else:
            try:
                ipaddress.ip_address(value)
                status = 'dns_answer'
            except ValueError:
                return
        # A positive address wins over intermediate CNAME/NODATA within this query.
        if row['status'] == 'dns_answer' and status in ('dns_cname', 'dns_nodata'):
            return
        row.update(status=status, last=now, evidence=value[:80])

    def observe_flows(self, rows, now):
        seen = set()
        for row in rows[:3000]:
            key = row.get('diag_id')
            if not key:
                continue
            seen.add(key)
            old = self.flows.get(key)
            up, down = max(0, row['up']), max(0, row['down'])
            # Only judge bytes observed since collection began, never old totals.
            if old is None:
                old = dict(first=now, up=up, down=down, activity=now, waiting=None,
                           received=bool(down), last=now)
                self.flows[key] = old
            if down > old['down']:
                old['received'] = True
                old['waiting'] = None
            if up > old['up'] and not old['received'] and old['waiting'] is None:
                old['waiting'] = now
            old.update(up=up, down=down, last=now)
            age = now - old['first']
            if old['received']:
                status = 'reply_seen'
            elif age >= 15 and up > 0:
                status = 'no_reply'
            elif up == 0:
                status = 'idle'
            else:
                status = 'waiting'
            self.record(key, dict(kind='connection', device=row['device'],
                domain=row.get('domain', ''), destination=row.get('destination', '')[:64],
                port=str(row.get('port', ''))[:8], first=old['first'], last=now,
                status=status, route=row['route'], source=row['source'],
                protocol=row['protocol'], up=up, down=down,
                evidence='sampled_15s' if status == 'no_reply' else ''))
        for key in list(self.flows):
            if key not in seen:
                r = self.rows.get(key)
                if r and r['status'] in ('waiting', 'idle'):
                    r.update(status='ended_unconfirmed', last=now)
                del self.flows[key]

    def snapshot(self, now, health):
        for ident, key in list(self.pending.items()):
            row = self.rows.get(key)
            if row is None or now - row['first'] > 30:
                if row and row['status'] == 'dns_pending':
                    row.update(status='dns_unconfirmed', last=now)
                del self.pending[ident]
        for key in list(self.rows):
            if now - self.rows[key]['last'] > RETENTION:
                del self.rows[key]
        data = dict(time=now, started=self.started, retention_seconds=RETENTION,
                    max_rows=MAX_ROWS, dropped=self.dropped, health=health,
                    rows=list(self.rows.values()))
        temp = self.path.with_suffix('.new')
        with temp.open('w', encoding='utf-8') as f:
            os.chmod(temp, 0o600)
            json.dump(data, f, ensure_ascii=False, separators=(',', ':'))
        os.replace(temp, self.path)

def report(config, args):
    device = str(args.get('device', ''))
    if len(device) > 64:
        raise ValueError('Invalid device')
    path = pathlib.Path(config['runtime']) / 'diagnostics.json'
    if not path.exists():
        return {'rows': [], 'starting': True}
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('Diagnostics snapshot too large')
    data = json.loads(path.read_text())
    data['rows'] = [r for r in data['rows'] if device and r['device'] == device]
    data['rows'].sort(key=lambda r: r['last'], reverse=True)
    data['stale'] = time.time() - data['time'] > 30
    return data
