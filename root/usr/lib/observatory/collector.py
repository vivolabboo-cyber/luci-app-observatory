#!/usr/bin/python3
"""Local monitoring with counter-only nft chains; requires root. No cloud uploads."""
import collections
import datetime
import ipaddress
import json
import os
import pathlib
import re
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.request
import urllib.error

VERSION = '0.2.1'
CONFIG = '/etc/observatory/config.json'
STOP = False

LANGUAGE = 'en'
_MESSAGES = None
def message(key):
    global _MESSAGES
    if _MESSAGES is None:
        path=pathlib.Path('/usr/share/observatory/i18n')/('ru.json' if LANGUAGE=='ru' else 'en.json')
        try:_MESSAGES=json.loads(path.read_text())
        except (OSError,ValueError):_MESSAGES={}
    return _MESSAGES.get(key,key)


def command(args, timeout=5):
    return subprocess.check_output(args, timeout=timeout, stderr=subprocess.DEVNULL).decode(errors='replace')

def read(path, default=''):
    try:
        return pathlib.Path(path).read_text(errors='replace')
    except OSError:
        return default

def atomic_json(path, value):
    target = pathlib.Path(path)
    temp = target.with_suffix('.new')
    temp.write_text(json.dumps(value, ensure_ascii=False, separators=(',', ':')))
    os.chmod(temp, 0o600)
    os.replace(temp, target)

def address(value):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None

def external(value):
    ip = address(value)
    return bool(ip and not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)
                and (ip.is_global or value.startswith('198.18.') or value.startswith('198.19.')))

def hostname(value):
    value = str(value or '').lower().rstrip('.')
    return value if len(value) <= 253 and re.fullmatch(r'[a-z0-9_.-]+', value) and not address(value) else ''

def service(domain):
    groups = [('YouTube', ['youtube.com','googlevideo.com','ytimg.com','youtu.be']),
              ('Twitch', ['twitch.tv','ttvnw.net','jtvnw.net','twitchcdn.net']),
              ('Chrome Remote Desktop', ['remotedesktop.google.com','remotedesktop-pa.googleapis.com','instantmessaging-pa.googleapis.com','talkgadget.google.com']),
              ('ChatGPT / OpenAI', ['chatgpt.com','openai.com','oaistatic.com','oaiusercontent.com','sora.com']),
              ('Telegram', ['telegram.org','t.me']), ('Discord', ['discord.com','discord.gg','discordapp.net','discordapp.com']),
              ('Google', ['google.com','googleapis.com','gstatic.com','googleusercontent.com','google.ru','google','goog']),
              ('Instagram', ['instagram.com','cdninstagram.com']), ('Spotify', ['spotify.com','scdn.co']),
              ('Claude', ['claude.ai','anthropic.com','claude.com']), ('Steam', ['steampowered.com','steamcontent.com','steamcommunity.com'])]
    for label, suffixes in groups:
        if any(domain == s or domain.endswith('.'+s) for s in suffixes):
            return label
    return domain or message('b_accd672b7bb2')

def route_name(chains):
    text = ' '.join(str(x) for x in chains).lower()
    if 'youtube-out' in text or 'zapret' in text:
        return 'zapret2'
    if any(s in text for s in ['vpn','vless','proxy','crd_']):
        return 'vpn'
    if any(s in text for s in ['direct','bypass']):
        return 'direct'
    return 'unknown'

def parse_conntrack(line):
    pairs = re.findall(r'\b(src|dst|sport|dport|bytes|packets)=([^ ]+)', line)
    fields = collections.defaultdict(list)
    for key, val in pairs:
        fields[key].append(val)
    if not fields['src'] or not fields['dst']:
        return None
    def first(k, default='0'):
        return fields[k][0] if fields[k] else default
    try:
        return {'src':first('src'),'dst':first('dst'),'sport':first('sport'),'port':first('dport'),
                'up':int(first('bytes')), 'down':int(fields['bytes'][1]) if len(fields['bytes'])>1 else 0,
                'protocol':'udp' if ' udp ' in line else 'tcp' if ' tcp ' in line else 'other'}
    except ValueError:
        return None

def load_device_totals(db, since):
    return {device:[up or 0,down or 0] for device,up,down in db.execute(
        'SELECT device,SUM(up),SUM(down) FROM totals WHERE t>=? GROUP BY device',(since,))}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Local API endpoints must never redirect requests (including auth headers)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'Redirect rejected', headers, fp)

class Monitor:
    def __init__(self, config):
        self.cfg=config
        self.interface=config['interface']
        if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,32}',self.interface):
            raise ValueError('invalid interface')
        self.runtime=pathlib.Path(config['runtime']); self.runtime.mkdir(mode=0o700,parents=True,exist_ok=True); os.chmod(self.runtime,0o700)
        self.store=pathlib.Path(config['store']); self.store.mkdir(mode=0o700,parents=True,exist_ok=True); os.chmod(self.store,0o700)
        self.db=sqlite3.connect(self.store/'history.sqlite')
        os.chmod(self.store/'history.sqlite',0o600)
        self.db.executescript('''PRAGMA journal_mode=DELETE; PRAGMA synchronous=NORMAL;
        CREATE TABLE IF NOT EXISTS metrics(t INTEGER PRIMARY KEY, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS usage(t INTEGER, device TEXT, domain TEXT, service TEXT, route TEXT, source TEXT, up INTEGER, down INTEGER, PRIMARY KEY(t,device,domain,route,source));
        CREATE TABLE IF NOT EXISTS totals(t INTEGER, device TEXT, up INTEGER, down INTEGER, PRIMARY KEY(t,device));
        CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, name TEXT, ips TEXT, seen INTEGER);
        CREATE TABLE IF NOT EXISTS events(t INTEGER, kind TEXT, message TEXT);
        CREATE INDEX IF NOT EXISTS usage_t ON usage(t);
        ''')
        self.db.commit()
        self.started=int(time.time()); self.last_flush=time.time(); self.last_metric=0; self.last_discovery=0; self.last_maintenance=0
        self.devices={}; self.ip_device={}; self.counter_ips=set(); self.counters={}; self.device_totals=collections.defaultdict(lambda:[0,0])
        self.pending_usage=collections.defaultdict(lambda:[0,0]); self.pending_totals=collections.defaultdict(lambda:[0,0]); self.observed={}
        self.queries={}; self.dns_ips=collections.defaultdict(dict); self.dns_offset=0; self.dns_inode=None
        self.events=collections.deque(maxlen=30); self.errors={}; self.flow_rows=[]; self.last_cpu=None; self.net_prev={}; self.last_system={}; self.active=0
        self.events.extend({'time':r[0],'kind':r[1],'message':r[2]} for r in self.db.execute('SELECT t,kind,message FROM events ORDER BY t DESC LIMIT 30'))
        self.nft_ok=False; self.clash_ok=False; self.conntrack_ok=False; self.last_clash_warning=0
        self.api_previous=None; self.route_previous={}; self.link_previous={}
        self.last_rpc_check=0; self.last_rpc_repair=0; self.rpc_registered=True
        for row in self.db.execute('SELECT id,name,ips,seen FROM devices'):
            try:self.devices[row[0]]={'id':row[0],'name':row[1],'ips':json.loads(row[2]),'seen':row[3]}
            except (ValueError,TypeError):pass
        self.device_totals.update(load_device_totals(self.db,self.day_start()))
        self.day=self.day_start()
        self.setup_nft()

    @staticmethod
    def day_start():
        now=datetime.datetime.now();return int(now.replace(hour=0,minute=0,second=0,microsecond=0).timestamp())

    def check_rpc_registration(self):
        """rpcd can lose exec plugin registration during package/service reloads."""
        now=time.time()
        if now-self.last_rpc_check<60:return
        self.last_rpc_check=now
        def available():
            try:return 'observatory' in command(['ubus','list','observatory'],timeout=3).splitlines()
            except (OSError,subprocess.SubprocessError):return False
        self.rpc_registered=available()
        if self.rpc_registered:
            self.errors.pop('rpc',None)
            return
        self.errors['rpc']=message('b_89644c88e7e4')
        return  # Report only; never reload or restart rpcd automatically.

    def event(self, kind, msg):
        item={'time':int(time.time()),'kind':kind,'message':msg};self.events.appendleft(item)
        self.db.execute('INSERT INTO events VALUES(?,?,?)',(item['time'],kind,msg))

    def setup_nft(self):
        try:
            # No accept/drop/mark/redirect rules. A separate table owns counters only.
            subprocess.run(['nft','delete','table','inet','observatory'],stderr=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
            script='table inet observatory {\n chain device_tx { type filter hook prerouting priority -310; policy accept; }\n chain device_rx { type filter hook postrouting priority 310; policy accept; }\n}\n'
            subprocess.run(['nft','-f','-'],input=script,text=True,check=True,capture_output=True)
            self.counter_ips.clear(); self.counters.clear();self.nft_ok=True
        except (OSError,subprocess.SubprocessError) as exc:
            self.nft_ok=False;self.errors['counters']=str(exc)[:160]

    def discover(self):
        if not self.nft_ok:self.setup_nft()
        now=int(time.time()); found={}
        for line in read('/tmp/dhcp.leases').splitlines():
            parts=line.split()
            if len(parts)>=4 and address(parts[2]):found[parts[2]]=(parts[1].lower(),parts[3] if parts[3]!='*' else '')
        try:
            for row in json.loads(command(['ip','-j','neigh','show','dev',self.interface])):
                ip=row.get('dst','');mac=row.get('lladdr','').lower()
                if address(ip) and re.fullmatch(r'[0-9a-f]{2}(:[0-9a-f]{2}){5}',mac):
                    found[ip]=(mac,found.get(ip,('', ''))[1])
        except (OSError,ValueError,subprocess.SubprocessError):pass
        for ip,(mac,name) in found.items():
            if mac not in self.devices:self.event('device',message('b_b32c1f1fdfa9')+(name or mac)+' ('+ip+')')
            obj=self.devices.setdefault(mac,{'id':mac,'name':name or mac,'ips':[],'seen':now})
            if name:obj['name']=name
            if ip not in obj['ips']:obj['ips'].append(ip)
            obj['ips']=obj['ips'][-12:];obj['seen']=now;self.ip_device[ip]=mac
            if ip not in self.counter_ips:self.add_counter(ip)
        # Include devices discovered in previous runs, but only addresses currently belonging to them.
        self.last_discovery=time.time()

    def add_counter(self, ip):
        if not self.nft_ok:return
        ident=address(ip)
        if not ident:return
        family='ip' if ident.version==4 else 'ip6'
        name='a'+ident.packed.hex()
        script=f'add counter inet observatory {name}_u\nadd counter inet observatory {name}_d\n'
        script+=f'add rule inet observatory device_tx iifname "{self.interface}" {family} saddr {ip} counter name {name}_u\n'
        script+=f'add rule inet observatory device_rx oifname "{self.interface}" {family} daddr {ip} counter name {name}_d\n'
        try:
            subprocess.run(['nft','-f','-'],input=script,text=True,check=True,capture_output=True)
            self.counter_ips.add(ip);self.counters[name]=[ip,0,0]
        except (OSError,subprocess.SubprocessError):self.errors['counters']=message('b_b0d59c462f3a')

    def sample_counters(self):
        try:
            data=json.loads(command(['nft','-j','list','counters','table','inet','observatory']))
            latest={}
            for item in data.get('nftables',[]):
                value=item.get('counter',{}); name=value.get('name','')
                if re.fullmatch(r'a[0-9a-f]+_[ud]',name):latest[name]=int(value.get('bytes',0))
            minute=int(time.time())//60*60
            for key, entry in self.counters.items():
                ip,prev_u,prev_d=entry;up=latest.get(key+'_u',prev_u);down=latest.get(key+'_d',prev_d)
                if ip not in self.ip_device:continue
                dev=self.ip_device[ip]; delta=[max(0,up-prev_u),max(0,down-prev_d)]
                self.device_totals[dev][0]+=delta[0];self.device_totals[dev][1]+=delta[1]
                self.pending_totals[(minute,dev)][0]+=delta[0];self.pending_totals[(minute,dev)][1]+=delta[1]
                entry[1:]=[up,down]
            self.nft_ok=True
        except (OSError,ValueError,subprocess.SubprocessError):
            self.nft_ok=False;self.errors['counters']=message('b_aaaf09216bc6')

    def parse_dns(self, line, now):
        query=re.search(r'query\[[^]]+\]\s+(\S+)\s+from\s+(\S+)',line)
        if query:
            domain=hostname(query[1]);ip=query[2]
            if domain and ip in self.ip_device:self.queries[domain]=(self.ip_device[ip],now)
        answer=re.search(r'(?:reply|cached)\s+(\S+)\s+is\s+(\S+)',line)
        if answer:
            domain=hostname(answer[1]);ip=answer[2]
            if domain in self.queries and address(ip):
                dev,t=self.queries[domain]
                if now-t<15:self.dns_ips[(dev,ip)][domain]=now

    def sample_dns(self):
        if not self.cfg.get("dns_enabled",False):return
        path=pathlib.Path(self.cfg['dns_log'])
        try:
            st=path.stat()
            if self.dns_inode is None:
                # Ignore pre-start queries: they must not look like fresh activity after a restart.
                self.dns_inode=st.st_ino;self.dns_offset=st.st_size
                return
            if st.st_ino!=self.dns_inode or st.st_size<self.dns_offset:self.dns_offset=0;self.dns_inode=st.st_ino
            with path.open(errors='replace') as f:
                f.seek(self.dns_offset)
                for line in f:self.parse_dns(line,int(time.time()))
                self.dns_offset=f.tell()
            self.errors.pop('dns',None)
            if st.st_size>2*1024*1024:
                with path.open('w'):pass
                self.dns_offset=0
        except OSError:self.errors['dns']=message('b_c78703912c7a')
        now=time.time()
        self.queries={k:v for k,v in self.queries.items() if now-v[1]<30}
        for key in list(self.dns_ips):
            self.dns_ips[key]={d:t for d,t in self.dns_ips[key].items() if now-t<300}
            if not self.dns_ips[key]:del self.dns_ips[key]

    def clash_connections(self):
        if not self.cfg.get("tachyon_enabled",False):return []
        try:
            cfg=json.loads(read('/etc/tachyon-core/config.json','{}'))
            api=cfg.get('experimental',{}).get('clash_api',{})
            controller=api.get('external_controller','')
            host,port=controller.rsplit(':',1); host=host.strip('[]')
            ip=address(host)
            if not ip or not (ip.is_loopback or ip.is_unspecified) or not 1<=int(port)<=65535:return []
            if host=='0.0.0.0':host='127.0.0.1'
            if host=='::':host='::1'
            if ':' in host:host='['+host+']'
            headers={}
            if api.get('secret'):headers['Authorization']='Bearer '+api['secret']
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
            req=urllib.request.Request(f'http://{host}:{port}/connections',headers=headers)
            with opener.open(req,timeout=2) as response:
                payload=json.loads(response.read(4*1024*1024))
            self.clash_ok=True;return payload.get('connections',[])[:3000]
        except (OSError,ValueError,KeyError):
            self.clash_ok=False;return []

    def observe(self,key,dev,domain,route,source,up,down,proto,dst,port):
        now=int(time.time());prev=self.observed.get(key)
        delta_u=max(0,up-(prev[0] if prev else 0));delta_d=max(0,down-(prev[1] if prev else 0))
        # Existing connections on the first sample establish a baseline, not retroactive history.
        if now-self.started<self.cfg['interval']*2 and not prev:delta_u=delta_d=0
        self.observed[key]=(up,down,now)
        if domain and route!='unknown':
            route_key=(dev,domain)
            old=self.route_previous.get(route_key)
            if old and old!=route:self.event('route',self.devices.get(dev,{}).get('name',dev)+': '+domain+' — '+old+' → '+route)
            if len(self.route_previous)<5000:self.route_previous[route_key]=route
        if delta_u or delta_d:
            record=(now//60*60,dev,domain,service(domain),route,source)
            self.pending_usage[record][0]+=delta_u;self.pending_usage[record][1]+=delta_d
        self.flow_rows.append({'device':dev,'domain':domain,'service':service(domain),'destination':dst,'port':str(port),'protocol':proto,
                               'route':route,'source':source,'up':up,'down':down,'seen':now})

    def sample_flows(self):
        if not self.cfg.get("collect_connection_details",False):
            self.flow_rows=[]; self.active=0; return
        self.flow_rows=[];seen_tuples=set()
        connections=self.clash_connections()
        if self.api_previous is not None and self.api_previous!=self.clash_ok:
            self.event('tachyon',message('b_8af881960bfa') if self.clash_ok else message('b_448595ceec1b'))
        self.api_previous=self.clash_ok
        for item in connections:
            meta=item.get('metadata',{});ip=str(meta.get('sourceIP',''));dev=self.ip_device.get(ip)
            if not dev:continue
            domain=hostname(meta.get('host','') or meta.get('sniffHost',''));dst=str(meta.get('destinationIP',''));sport=str(meta.get('sourcePort',''));port=str(meta.get('destinationPort',''))
            seen_tuples.add((ip,sport,str(meta.get('network','tcp'))))
            self.observe('api:'+str(item.get('id','')),dev,domain,route_name(item.get('chains',[])),
                         'Tachyon' if domain else message('b_2f646cb43f2b'),int(item.get('upload',0)),int(item.get('download',0)),str(meta.get('network','tcp')),dst,port)
        text=read('/proc/net/nf_conntrack')
        self.conntrack_ok=bool(text)
        for line in text.splitlines()[:20000]:
            row=parse_conntrack(line)
            if not row or row['src'] not in self.ip_device or not external(row['dst']):continue
            dev=self.ip_device[row['src']]
            if (row['src'],row['sport'],row['protocol']) in seen_tuples:continue
            # FakeIP / tproxy connections without API metadata must not be counted twice.
            if row['dst'].startswith(('198.18.','198.19.')):continue
            names=self.dns_ips.get((dev,row['dst']),{})
            domain=next(iter(names)) if len(names)==1 else ''
            key='ct:'+':'.join([row['src'],row['sport'],row['dst'],row['port'],row['protocol']])
            self.observe(key,dev,domain,'unknown',message('b_52f1ddf8528d') if domain else message('b_2f646cb43f2b'),row['up'],row['down'],row['protocol'],row['dst'],row['port'])
        now=time.time();self.observed={k:v for k,v in self.observed.items() if now-v[2]<60}
        self.flow_rows.sort(key=lambda r:r['down']+r['up'],reverse=True)
        self.active=len(self.flow_rows);self.flow_rows=self.flow_rows[:200]

    def system(self):
        now=time.time(); fields=read('/proc/stat').splitlines()[0].split()[1:]
        vals=[int(x) for x in fields]; total=sum(vals[:8]); idle=vals[3]+(vals[4] if len(vals)>4 else 0);cpu=0
        if self.last_cpu:
            elapsed=total-self.last_cpu[0]
            cpu=round(100*(1-(idle-self.last_cpu[1])/elapsed),1) if elapsed>0 else 0
        self.last_cpu=(total,idle)
        mem={k:int(v.split()[0])*1024 for k,v in (line.split(':',1) for line in read('/proc/meminfo').splitlines())}
        disk=os.statvfs('/'); interfaces=[]
        for name in dict.fromkeys([self.interface,self.cfg.get('wan_interface','eth1')]):
            base='/sys/class/net/'+name+'/';rx=int(read(base+'statistics/rx_bytes','0'));tx=int(read(base+'statistics/tx_bytes','0'))
            prev=self.net_prev.get(name);dt=max(.1,now-prev[2]) if prev else 1
            interfaces.append({'name':name,'rx':rx,'tx':tx,'rx_bps':max(0,rx-prev[0])/dt if prev else 0,'tx_bps':max(0,tx-prev[1])/dt if prev else 0,
                               'errors':int(read(base+'statistics/rx_errors','0'))+int(read(base+'statistics/tx_errors','0')),
                               'drops':int(read(base+'statistics/rx_dropped','0'))+int(read(base+'statistics/tx_dropped','0')),
                               'speed':read(base+'speed').strip(),'state':read(base+'operstate').strip()})
            self.net_prev[name]=(rx,tx,now)
            link_state=interfaces[-1]['state']
            if name in self.link_previous and self.link_previous[name]!=link_state:
                self.event('link',name+': '+self.link_previous[name]+' → '+link_state)
            self.link_previous[name]=link_state
        temperature=read('/sys/class/thermal/thermal_zone0/temp','0')
        result={'cpu':max(0,min(cpu,100)),'load':read('/proc/loadavg').split()[:3], 'memory_total':mem.get('MemTotal',0),'memory_used':mem.get('MemTotal',0)-mem.get('MemAvailable',0),
                'temperature':round(float(temperature)/1000,1),'uptime':float(read('/proc/uptime','0').split()[0]),
                'disk_total':disk.f_blocks*disk.f_frsize,'disk_free':disk.f_bavail*disk.f_frsize,'interfaces':interfaces,
                'version':re.search(r"DISTRIB_RELEASE='([^']+)'",read('/etc/openwrt_release')).group(1),'hostname':read('/proc/sys/kernel/hostname').strip()}
        if now-self.last_metric>=60:
            self.db.execute('INSERT OR REPLACE INTO metrics VALUES(?,?)',(int(now)//60*60,json.dumps(result)));self.last_metric=now
        return result

    def flush(self):
        for (t,dev),values in self.pending_totals.items():
            self.db.execute('INSERT INTO totals VALUES(?,?,?,?) ON CONFLICT(t,device) DO UPDATE SET up=up+excluded.up,down=down+excluded.down',(t,dev,*values))
        for (t,dev,domain,label,route,source),values in self.pending_usage.items():
            self.db.execute('INSERT INTO usage VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(t,device,domain,route,source) DO UPDATE SET up=up+excluded.up,down=down+excluded.down',(t,dev,domain,label,route,source,*values))
        for dev,value in self.devices.items():
            self.db.execute('INSERT OR REPLACE INTO devices VALUES(?,?,?,?)',(dev,value['name'],json.dumps(value['ips']),value['seen']))
        self.db.commit();self.pending_totals.clear();self.pending_usage.clear();self.last_flush=time.time()
        if time.time()-self.last_maintenance>3600:
            cutoff=int(time.time())-self.cfg['retention_days']*86400
            for table in ['usage','totals','metrics','events']:self.db.execute('DELETE FROM '+table+' WHERE t<?',(cutoff,))
            if (self.store/'history.sqlite').stat().st_size>self.cfg['max_database_mb']*1024*1024:
                # Bounded oldest-day eviction; vacuum hourly only after the cap is reached.
                oldest=self.db.execute('SELECT MIN(t) FROM metrics').fetchone()[0]
                if oldest:
                    for table in ['usage','totals','metrics','events']:self.db.execute('DELETE FROM '+table+' WHERE t<?',(oldest+86400,))
                self.db.commit();self.db.execute('VACUUM')
            self.db.commit();self.last_maintenance=time.time()

    def snapshot(self):
        since=self.day_start(); usage={}
        for dev,domain,label,route,source,up,down in self.db.execute('SELECT device,domain,service,route,source,SUM(up),SUM(down) FROM usage WHERE t>=? GROUP BY device,domain,route,source',(since,)):
            usage[(dev,domain,label,route,source)]=[up or 0,down or 0]
        for key,val in self.pending_usage.items():
            if key[0]<since:continue
            group=key[1:];dest=usage.setdefault(group,[0,0]);dest[0]+=val[0];dest[1]+=val[1]
        sites=[dict(device=k[0],domain=k[1],service=k[2],route=k[3],source=k[4],up=v[0],down=v[1]) for k,v in usage.items()]
        sites.sort(key=lambda x:x['up']+x['down'],reverse=True)
        devices=[]
        for key,d in self.devices.items():
            up,down=self.device_totals[key];devices.append(dict(d,up=up,down=down,active=any(f['device']==key for f in self.flow_rows)))
        devices.sort(key=lambda d:d['up']+d['down'],reverse=True)
        history=[]
        for t,data in self.db.execute('SELECT t,data FROM metrics WHERE t>=? ORDER BY t',(int(time.time())-86400,)):
            metric=json.loads(data);wan=next((i for i in metric.get('interfaces',[]) if i['name']==self.cfg.get('wan_interface','eth1')),{})
            history.append({'time':t,'cpu':metric['cpu'],'temperature':metric['temperature'],'memory_used':metric['memory_used'],
                            'wan_rx_bps':wan.get('rx_bps',0),'wan_tx_bps':wan.get('tx_bps',0)})
        payload={'version':VERSION,'time':int(time.time()),'started':self.started,'period_start':max(since,self.started),'system':self.last_system,
                 'devices':devices,'sites':sites[:500],'flows':self.flow_rows,'events':list(self.events),'history':history[-1440:],
                 'health':{'nft_counters':self.nft_ok,'tachyon_api':self.clash_ok,'conntrack':self.conntrack_ok,'dns_log':bool(self.cfg.get('dns_enabled')) and pathlib.Path(self.cfg['dns_log']).exists(),
                           'rpc_registered':self.rpc_registered,
                           'retention_days':self.cfg['retention_days'],'flush_seconds':self.cfg['flush_seconds'],'interval':self.cfg['interval'],'errors':self.errors,
                           'collector_rss_kb':next((int(x.split()[1]) for x in read('/proc/self/status').splitlines() if x.startswith('VmRSS:')),0),
                           'database_bytes':(self.store/'history.sqlite').stat().st_size},
                 'limits':[message('b_61c524002564'),
                           message('b_9c4ba656c7c5'),
                           message('b_cb27d4c283cb'),
                           message('b_07e669d94433'),
                           message('b_2360103281e9')]}
        atomic_json(self.runtime/'snapshot.json',payload)

    def loop(self):
        self.event('startup',message('b_e2a4fe533dda'))
        while not STOP:
            begin=time.time()
            try:
                day=self.day_start()
                if day!=self.day:self.flush();self.device_totals.clear();self.day=day
                if begin-self.last_discovery>20:self.discover()
                self.check_rpc_registration()
                self.sample_dns();self.sample_counters();self.sample_flows();self.last_system=self.system()
                if begin-self.last_flush>=self.cfg['flush_seconds']:self.flush()
                self.errors.pop('collector',None)
                self.snapshot()
            except Exception as exc:
                self.errors['collector']=type(exc).__name__+': '+str(exc)[:180]
                print(self.errors['collector'],file=sys.stderr,flush=True)
            for _ in range(max(1,int((self.cfg['interval']-(time.time()-begin))*5))):
                if STOP:break
                time.sleep(.2)
        self.flush();self.db.close()

def main():
    os.umask(0o077)
    def stop(*_):
        global STOP
        STOP=True
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    config=json.loads(read(CONFIG))
    global LANGUAGE
    LANGUAGE=config.get("language","en")
    Monitor(config).loop()

if __name__=='__main__':main()
