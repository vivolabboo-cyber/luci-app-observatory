"""Refuse to publish an archive that differs from the pinned installer."""
import hashlib,pathlib,re,tarfile
r=pathlib.Path(__file__).resolve().parents[1]
version=(r/'VERSION').read_text().strip()
assert re.fullmatch(r'\d+\.\d+\.\d+',version)
installer=(r/'bootstrap.sh').read_text()
assert "VERSION='"+version+"'" in installer
archive=r/'dist'/('luci-app-observatory-'+version+'.tar.gz')
assert hashlib.sha256(archive.read_bytes()).hexdigest()==re.search(r"^SHA256='([a-f0-9]{64})'",installer,re.M)[1]
with tarfile.open(archive) as tf:
 for item in tf.getmembers():
  p=pathlib.PurePosixPath(item.name)
  assert not p.is_absolute() and '..' not in p.parts and item.isfile()
  assert '__pycache__' not in p.parts and p.suffix not in ['.pyc','.sqlite','.db','.key','.pem','.log']
  if '/init.d/' in item.name or item.name.endswith('/rpcd/observatory'):assert item.mode==0o755
print('Release archive, paths, executable modes and pinned checksum verified')
