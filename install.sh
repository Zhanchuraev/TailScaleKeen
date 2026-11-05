#!/bin/sh
# TailScaleKeen requires existing Entware; it never formats or reinstalls /opt.
set -eu
PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin:/bin:/sbin
export PATH PYTHONDONTWRITEBYTECODE=1
umask 077
source_dir=""
port=8092
panel_only=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --source) [ "$#" -ge 2 ] || exit 2; source_dir="$2"; shift 2;;
        --port) [ "$#" -ge 2 ] || exit 2; port="$2"; shift 2;;
        --panel-only) panel_only="--panel-only"; shift;;
        *) echo "Unknown option: $1" >&2; exit 2;;
    esac
done
case "$port" in ''|*[!0-9]*) echo 'Invalid port' >&2; exit 2;; esac
[ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || exit 2
[ "$(id -u)" = 0 ] || { echo 'Run as Entware root' >&2; exit 1; }
[ -x /opt/bin/opkg ] || { echo 'Install Entware aarch64-k3.10 first' >&2; exit 1; }
[ "$(uname -m)" = aarch64 ] || { echo 'Supported architecture: aarch64/arm64' >&2; exit 1; }
[ -d /opt/etc/init.d ] || { echo 'Entware init.d is missing' >&2; exit 1; }
if ! /opt/bin/python3 -c 'import http.server,ssl,urllib.request,hashlib,tarfile,fcntl' 2>/dev/null || ! command -v curl >/dev/null 2>&1; then
    opkg update
    opkg install python3 python3-urllib python3-openssl ca-bundle curl tar
fi
/opt/bin/python3 -c 'import sys; assert sys.version_info >= (3,11), "Python 3.11+ required"'
mkdir -p /opt/tmp
temp_dir=""
cleanup() { [ -z "$temp_dir" ] || rm -rf "$temp_dir"; }
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
if [ -z "$source_dir" ]; then
    temp_dir="$(mktemp -d /opt/tmp/tailscalekeen-install.XXXXXX)"
    base="https://github.com/Zhanchuraev/TailScaleKeen/releases/latest/download"
    curl -fLsS --connect-timeout 15 --max-time 180 --retry 2 "$base/tailscalekeen.tar.gz" -o "$temp_dir/release.tar.gz"
    curl -fLsS --connect-timeout 15 --max-time 60 --retry 2 "$base/tailscalekeen.tar.gz.sha256" -o "$temp_dir/release.sha256"
    /opt/bin/python3 - "$temp_dir" <<'PYBOOT'
import hashlib,io,json,pathlib,re,sys,tarfile
root=pathlib.Path(sys.argv[1]);blob=(root/'release.tar.gz').read_bytes()
expected=re.fullmatch(r'([a-fA-F0-9]{64})\s+\*?tailscalekeen\.tar\.gz', (root/'release.sha256').read_text().strip())
if len(blob)>8*1024*1024 or not expected or hashlib.sha256(blob).hexdigest()!=expected[1].lower():
    raise SystemExit('Release SHA256 mismatch or oversized release')
files={};total=0
with tarfile.open(fileobj=io.BytesIO(blob),mode='r:gz') as archive:
    for m in archive:
        p=pathlib.PurePosixPath(m.name)
        if m.isdir():continue
        total+=m.size
        if not m.isfile() or p.is_absolute() or '..' in p.parts or '\\' in m.name or str(p)!=m.name or m.name in files or total>20*1024*1024 or len(files)>100:
            raise SystemExit('Unsafe release archive')
        files[m.name]=archive.extractfile(m).read()
manifest=json.loads(files.pop('release-manifest.json'))
if set(files)!=set(manifest['files']):raise SystemExit('Release manifest mismatch')
for name,content in files.items():
    if hashlib.sha256(content).hexdigest()!=manifest['files'][name]:raise SystemExit('Release file checksum mismatch')
    p=root/'release'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(content)
    p.chmod(0o755 if name=='install.sh' or name.startswith('scripts/') else 0o644)
PYBOOT
    source_dir="$temp_dir/release"
fi
cd "$source_dir"
/opt/bin/python3 -m panel.install --source "$source_dir" --port "$port" ${panel_only:+--panel-only}
echo "TailScaleKeen installed. Open http://<router-LAN-IP>:$port/ (existing settings keep their port)."
echo 'First visit: create your own username and password, repeat it; minimum 6 characters.'
echo 'Full removal: tailscalekeen uninstall --purge'
