"""Read-only analytics and additive schema migration for Observatory."""
import collections
import datetime
import json
import math
import pathlib
import re
import time

VERSION = '0.3.0'


def migrate(db):
    columns = {r[1] for r in db.execute('PRAGMA table_info(events)')}
    for name, kind in [('device', 'TEXT'), ('domain', 'TEXT'), ('level', 'TEXT'), ('details', 'TEXT')]:
        if name not in columns:
            db.execute('ALTER TABLE events ADD COLUMN '+name+' '+kind)
    db.executescript('''
    CREATE INDEX IF NOT EXISTS events_t ON events(t);
    CREATE INDEX IF NOT EXISTS usage_device_t ON usage(device,t);
    CREATE INDEX IF NOT EXISTS totals_device_t ON totals(device,t);
    CREATE TABLE IF NOT EXISTS dns_queries(t INTEGER NOT NULL,device TEXT NOT NULL,domain TEXT NOT NULL,qtype TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS dns_queries_t ON dns_queries(t);
    CREATE INDEX IF NOT EXISTS dns_queries_device_t ON dns_queries(device,t);
    ''')
    db.commit()


def clean_device(value):
    value = str(value or '').lower()
    if value and not re.fullmatch(r'[0-9a-f]{2}(:[0-9a-f]{2}){5}', value):
        raise ValueError('Invalid device')
    return value


def window(query, hours, now, retention):
    day = int(datetime.datetime.fromtimestamp(now).replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    mode = query.get('period', '')
    if mode == 'today':
        start, end = day, now+1
    elif mode == 'yesterday':
        start, end = day-86400, day
    elif mode == 'custom':
        start, end = int(query['since']), int(query['until'])
    else:
        start, end = now-max(1, min(168, int(hours)))*3600, now+1
    if query.get('anchor_until') is not None and mode != 'custom':
        end = min(end, int(query['anchor_until']))
        if mode not in ('today', 'yesterday'):
            start = end-max(1, min(168, int(hours)))*3600
    if start >= end or start > now or end-start > max(1, retention)*86400+1:
        raise ValueError('Invalid time range')
    return max(start, now-max(1, retention)*86400), min(end, now+1)


def infer_event_device(message, devices):
    # Legacy rows have no structured device. Only infer unambiguous explicit identifiers.
    matches = []
    for d in devices:
        if d['id'] in message or (d.get('name') and message.startswith(d['name']+':')):
            matches.append(d['id'])
    return matches[0] if len(matches) == 1 else ''


def decorate_events(rows, devices):
    result = []
    for r in rows:
        d = dict(r)
        try:
            details = json.loads(d.get('details') or '{}')
        except (ValueError, TypeError):
            details = {}
        device = d.get('device') or infer_event_device(d['message'], devices)
        result.append(dict(id=d['id'], time=d['t'], kind=d['kind'], message=d['message'],
                           device=device, domain=d.get('domain') or '',
                           level=d.get('level') or ('warning' if 'недоступ' in d['message'] else 'info'),
                           details=details, legacy=not bool(d.get('details'))))
    return result


def registrable(domain, rules=None):
    if not domain:
        return ''
    if rules is None:
        # Keep the full hostname when no public-suffix data is available; never guess co.uk etc.
        return domain
    exact, wild, exceptions = rules
    labels = domain.lower().split('.')
    public = 1
    for i in range(len(labels)):
        tail = '.'.join(labels[i:])
        if tail in exceptions:
            public = len(labels)-i-1
            break
        if tail in exact:
            public = max(public, len(labels)-i)
        if i+1 < len(labels) and '.'.join(labels[i+1:]) in wild:
            public = max(public, len(labels)-i)
    return '.'.join(labels[-(public+1):])


def suffix_rules(path='/usr/share/tachyon/public-suffix-list.dat'):
    try:
        text = pathlib.Path(path).read_text()
    except OSError:
        return None
    exact, wild, exceptions = set(), set(), set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('//'):
            continue
        if line.startswith('!'):
            exceptions.add(line[1:])
        elif line.startswith('*.'):
            wild.add(line[2:])
        else:
            exact.add(line)
    return exact, wild, exceptions


def report(db, cfg, args, now=None):
    now = int(time.time()) if now is None else int(now)
    q = args.get('query') or {}
    if not isinstance(q, dict):
        raise ValueError('Invalid query')
    device = clean_device(args.get('device'))
    start, end = window(q, args.get('hours', 24), now, int(cfg.get('retention_days', 7)))
    base, params = 't>=? AND t<?', [start, end]
    where = base+(' AND device=?' if device else '')
    selected = params+([device] if device else [])
    search = str(q.get('search') or '').strip()[:160]
    search_sql = ''
    search_params = []
    if search:
        search_sql = " AND domain LIKE ? ESCAPE '\\'"
        search_params = ['%'+search.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')+'%']
    site_where, site_params = where+search_sql, selected+search_params
    known = [dict(id=r[0], name=r[1], ips=json.loads(r[2]), seen=r[3])
             for r in db.execute('SELECT id,name,ips,seen FROM devices')]
    sites = []
    for r in db.execute('''SELECT device,domain,service,route,source,SUM(up),SUM(down),MIN(t),MAX(t)
        FROM usage WHERE '''+site_where+''' GROUP BY device,domain,service,route,source
        ORDER BY SUM(up)+SUM(down) DESC LIMIT 2001''', site_params):
        sites.append(dict(device=r[0], domain=r[1], service=r[2], route=r[3], source=r[4],
                          up=r[5] or 0, down=r[6] or 0, first=r[7], last=r[8]))
    total_groups = db.execute('SELECT COUNT(*) FROM (SELECT 1 FROM usage WHERE '+site_where+
        ' GROUP BY device,domain,service,route,source)', site_params).fetchone()[0]
    source_totals = [dict(source=r[0], up=r[1] or 0, down=r[2] or 0)
        for r in db.execute('SELECT source,SUM(up),SUM(down) FROM usage WHERE '+where+' GROUP BY source', selected)]
    totals = [dict(device=r[0], up=r[1] or 0, down=r[2] or 0)
        for r in db.execute('SELECT device,SUM(up),SUM(down) FROM totals WHERE '+where+' GROUP BY device', selected)]
    # Global overview: hourly buckets. Device detail: at most 168 hourly buckets.
    history = [dict(time=r[0], up=r[1] or 0, down=r[2] or 0)
        for r in db.execute('SELECT (t/3600)*3600,SUM(up),SUM(down) FROM totals WHERE '+where+
                            ' GROUP BY (t/3600) ORDER BY 1', selected)]
    service_totals = [dict(service=r[0], up=r[1] or 0, down=r[2] or 0, domains=r[3])
        for r in db.execute('SELECT service,SUM(up),SUM(down),COUNT(DISTINCT domain) FROM usage WHERE '+site_where+
                            ' GROUP BY service ORDER BY SUM(up)+SUM(down) DESC', site_params)]
    step = max(60, math.ceil((end-start)/1440/60)*60)
    buckets = {}
    for timestamp, raw in db.execute('SELECT t,data FROM metrics WHERE '+base+' ORDER BY t', params):
        try:
            metric = json.loads(raw)
            wan = next((x for x in metric.get('interfaces', []) if x['name']==cfg.get('wan_interface', 'eth1')), {})
            values = [metric.get('cpu', 0), metric.get('temperature', 0), metric.get('memory_used', 0), wan.get('rx_bps', 0), wan.get('tx_bps', 0)]
            key = timestamp//step*step
            item = buckets.setdefault(key, {'time':timestamp, 'n':0, 'values':[0]*5})
            item['n'] += 1
            for i, value in enumerate(values): item['values'][i] += float(value or 0)
        except (ValueError, TypeError, KeyError):
            continue
    system_history = []
    for item in buckets.values():
        values = [round(v/item['n'], 2) for v in item['values']]
        system_history.append(dict(zip(['time','cpu','temperature','memory_used','wan_rx_bps','wan_tx_bps'], [item['time']]+values)))
    rules = suffix_rules()
    for row in sites:
        row['base_domain'] = registrable(row['domain'], rules)
    # Events have separate filters; device-specific filtering works for new and unambiguous legacy rows.
    columns = {r[1] for r in db.execute('PRAGMA table_info(events)')}
    extras = ',device,domain,level,details' if 'details' in columns else ',NULL AS device,NULL AS domain,NULL AS level,NULL AS details'
    event_rows = db.execute('SELECT rowid AS id,t,kind,message'+extras+' FROM events WHERE '+base+' ORDER BY t DESC,rowid DESC LIMIT 10001', params)
    ev = decorate_events((dict(zip([x[0] for x in event_rows.description], row)) for row in event_rows), known)
    event_limited = len(ev) > 10000
    ev = ev[:10000]
    kind = str(q.get('kind') or '')[:32]
    event_device = clean_device(q.get('event_device') or device)
    if kind:
        ev = [e for e in ev if e['kind'] == kind]
    if event_device:
        ev = [e for e in ev if e['device'] == event_device]
    if q.get('level') in ('warning', 'info'):
        ev = [e for e in ev if e['level'] == q['level']]
    event_total = len(ev)
    offset = max(0, min(100000, int(q.get('event_offset', 0))))
    ev = ev[offset:offset+100]
    activity_offset = max(0, min(100000, int(q.get('activity_offset', 0))))
    activity = [dict(time=r[0], device=r[1], domain=r[2], service=r[3], route=r[4], source=r[5], up=r[6], down=r[7])
        for r in db.execute('SELECT t,device,domain,service,route,source,up,down FROM usage WHERE '+where+search_sql+
                            ' ORDER BY t DESC,device,domain,route,source LIMIT 101 OFFSET ?', selected+search_params+[activity_offset])]
    dns = []
    dns_count = 0
    dns_first = None
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='dns_queries'").fetchone():
        dns_count = db.execute('SELECT COUNT(*) FROM dns_queries WHERE '+where+search_sql, selected+search_params).fetchone()[0]
        dns = [dict(time=r[0], device=r[1], domain=r[2], qtype=r[3]) for r in db.execute(
            'SELECT t,device,domain,qtype FROM dns_queries WHERE '+where+search_sql+
            ' ORDER BY t DESC,rowid DESC LIMIT 101 OFFSET ?', selected+search_params+[activity_offset])]
        dns_first = db.execute('SELECT MIN(t) FROM dns_queries').fetchone()[0]
    first_sample = db.execute('SELECT MIN(t) FROM metrics').fetchone()[0]
    return dict(version=VERSION, since=start, until=end, time=now, device=device, sites=sites[:2000],
                total_groups=total_groups, sites_truncated=total_groups>2000,
                source_totals=source_totals, service_totals=service_totals, totals=totals,
                devices=known, device_history=history, system_history=system_history, first_sample=first_sample,
                events=ev, event_total=event_total, event_offset=offset, event_limited=event_limited,
                activity=activity[:100], activity_more=len(activity)>100,
                dns_queries=dns[:100], dns_more=len(dns)>100, dns_count=dns_count, dns_first=dns_first,
                dns_retention_days=2, note='Traffic history has minute precision. DNS queries are not visits. The latest minute may not be saved yet.')
