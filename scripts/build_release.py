"""Reproducible allowlisted release; never package runtime state or ops."""
import gzip,hashlib,io,json,pathlib,sys,tarfile
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from panel.releases import ARCHIVE, allowed_file, DOCS
from panel.core import VERSION
ROOT=pathlib.Path(__file__).resolve().parents[1]

def build(root=ROOT):
    root=pathlib.Path(root)
    if (root/'VERSION').read_text().strip()!=VERSION:raise ValueError('VERSION mismatch')
    paths=[p for p in root.rglob('*') if p.is_file() and allowed_file(p.relative_to(root).as_posix())]
    files={p.relative_to(root).as_posix():p.read_bytes() for p in paths}
    if not DOCS<=set(files):raise ValueError('Required documentation missing')
    files['release-manifest.json']=(json.dumps({'version':VERSION,'files':{n:hashlib.sha256(b).hexdigest() for n,b in sorted(files.items())}},sort_keys=True,indent=2)+'\n').encode()
    directory=root/'dist';directory.mkdir(exist_ok=True)
    output=directory/ARCHIVE
    with output.open('wb') as f,gzip.GzipFile(filename='',fileobj=f,mode='wb',mtime=0) as gz,tarfile.open(fileobj=gz,mode='w') as archive:
        for name,blob in sorted(files.items()):
            info=tarfile.TarInfo(name);info.size=len(blob);info.mode=0o755 if name=='install.sh' or name.startswith('scripts/') else 0o644
            info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
            archive.addfile(info,io.BytesIO(blob))
    digest=hashlib.sha256(output.read_bytes()).hexdigest()
    (directory/(ARCHIVE+'.sha256')).write_text(digest+'  '+ARCHIVE+'\n',encoding='ascii')
    print(ARCHIVE,output.stat().st_size,digest)
    return output

if __name__=='__main__':build()
