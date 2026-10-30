#!/usr/bin/env python3
from pathlib import Path
import ast,json,re
r=Path(__file__).resolve().parents[1]
for p in r.rglob('*'):
    if not p.is_file() or '.git' in p.parts or 'dist' in p.parts:continue
    if p.suffix=='.json':json.loads(p.read_text('utf-8'))
    if p.suffix=='.py' or p.as_posix().endswith('/rpcd/observatory'):ast.parse(p.read_text('utf-8'),filename=str(p))
    if p.suffix in ('.key','.pem','.sqlite','.db','.log'):raise SystemExit('Forbidden runtime file: '+str(p))
    if p.suffix in ('.js','.py','.json','.html','.ut','.md','.sh',''):
        s=p.read_text('utf-8',errors='ignore')
        forbidden=[r'-----BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY-----',r'gh[pousr]_[A-Za-z0-9]{30,}',r'github_pat_[A-Za-z0-9_]{30,}',r'\b[0-9]{8,12}:[A-Za-z0-9_-]{30,}\b']
        if any(re.search(x,s) for x in forbidden):raise SystemExit('Potential secret in '+str(p))
print('Source validation passed')
