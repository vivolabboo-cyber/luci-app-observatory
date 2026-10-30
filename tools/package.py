#!/usr/bin/env python3
"""Build a source-controlled, allowlisted tarball. Never packages runtime data."""
from pathlib import Path
import tarfile,hashlib
ROOT=Path(__file__).resolve().parents[1]
version=(ROOT/'VERSION').read_text().strip()
dest=ROOT/'dist';dest.mkdir(exist_ok=True)
archive=dest/(ROOT.name+'-'+version+'.tar.gz')
with tarfile.open(archive,'w:gz') as tf:
    for base in ['root','install.sh','uninstall.sh','LICENSE','NOTICE','README.md','README.en.md','config']:
        path=ROOT/base
        if not path.exists():continue
        items=path.rglob('*') if path.is_dir() else [path]
        for item in sorted(items):
            if not item.is_file() or item.is_symlink():continue
            if item.suffix in ('.db','.sqlite','.log','.key','.pem') or item.name in ('config.json','config.local.json'):raise SystemExit('Runtime file blocked: '+str(item))
            info=tf.gettarinfo(str(item),arcname=item.relative_to(ROOT).as_posix())
            info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=0
            info.mode=0o755 if item.name.endswith('.sh') or '/init.d/' in str(item) or '/rpcd/observatory' in str(item) else 0o644
            with item.open('rb') as f:tf.addfile(info,f)
digest=hashlib.sha256(archive.read_bytes()).hexdigest()
(dest/'SHA256SUMS').write_text(digest+'  '+archive.name+'\n')
print(archive)
