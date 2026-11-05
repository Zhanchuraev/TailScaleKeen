"""Conservative public-tree gate, independent of .gitignore and git add."""
import pathlib,re,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
TOP={'README.md','README.ru.md','LICENSE','VERSION','CHANGELOG.md','SECURITY.md','THIRD_PARTY.md','install.sh','.gitignore','.gitattributes'}

def public_files(root=ROOT):
    result=[]
    for p in pathlib.Path(root).rglob('*'):
        if not p.is_file():continue
        relative=p.relative_to(root).as_posix()
        if relative in TOP or relative.startswith(('panel/','web/','tests/','scripts/','.github/workflows/')):
            if '__pycache__' in p.parts or p.suffix=='.pyc':continue
            result.append(p)
    return sorted(result)

def check(root=ROOT):
    problems=[];paths=public_files(root)
    forbidden=re.compile(r'(?:vless|vmess|trojan)://|-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{24,}|github_pat_[A-Za-z0-9_]{30,}|tskey-(?:auth|api)-[A-Za-z0-9_-]{20,}')
    for p in paths:
        name=p.relative_to(root).as_posix()
        if p.is_symlink() or any(x in p.name.lower() for x in ['.private.','.dpapi','credentials']) or p.suffix in ['.state','.key','.pem','.log']:
            problems.append(name+': prohibited file')
        if p.suffix not in ['.ttf'] and p.name!='check_public.py':
            if forbidden.search(p.read_text(encoding='utf-8')):problems.append(name+': possible secret or subscription')
    if problems:raise ValueError('\n'.join(problems))
    print('Public allowlist:',len(paths),'files; no prohibited runtime files or recognized secrets')
    return paths

if __name__=='__main__':check()
