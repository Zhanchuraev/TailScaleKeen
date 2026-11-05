import copy,hashlib,io,json,pathlib,sys,tarfile,tempfile,time,unittest
from unittest.mock import patch
from panel.core import Error,VERSION,write_json,read_json,Jobs
from panel.releases import ARCHIVE,REPOSITORY,release_info,unpack_release,fetch_release,allowed_file
from panel.panel_update import apply_staged,PanelUpdater
from scripts.build_release import build

ROOT=pathlib.Path(__file__).resolve().parents[1]

def blob(files,extra=None):
    buf=io.BytesIO()
    with tarfile.open(fileobj=buf,mode='w:gz') as t:
        for name,content in files.items():
            if isinstance(content,str):content=content.encode()
            m=tarfile.TarInfo(name);m.size=len(content);t.addfile(m,io.BytesIO(content))
        if extra:t.addfile(extra)
    return buf.getvalue()

def files():
    f={p.relative_to(ROOT).as_posix():p.read_bytes() for p in ROOT.rglob('*') if p.is_file() and allowed_file(p.relative_to(ROOT).as_posix())}
    f['release-manifest.json']=json.dumps({'version':VERSION,'files':{n:hashlib.sha256(b).hexdigest() for n,b in f.items()}}).encode()
    return f


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name)

    def test_isolated_server_cannot_launch_production_self_update(self):
        with patch('panel.panel_update.release_info') as fetch, self.assertRaises(Error):
            PanelUpdater(self.root).prepare(lambda _:None)
        self.assertFalse(fetch.called)

    def test_valid_archive_and_reproducible_build(self):
        path=build();one=path.read_bytes();self.assertEqual(one,build().read_bytes())
        m=unpack_release(one,self.root/'candidate',VERSION)
        self.assertEqual(m['version'],VERSION)
        self.assertFalse((self.root/'candidate'/'tests').exists())
        self.assertFalse((self.root/'candidate'/'ops').exists())

    def test_traversal_symlinks_duplicates_and_missing_files_rejected(self):
        for kind in ['traversal','symlink','duplicate','missing','extra']:
            with self.subTest(kind=kind):
                f=files();extra=None
                if kind=='traversal':f['../escape']=b'bad'
                elif kind=='symlink':
                    extra=tarfile.TarInfo('panel/link.py');extra.type=tarfile.SYMTYPE;extra.linkname='/etc/passwd'
                elif kind=='duplicate':
                    extra=tarfile.TarInfo('VERSION');extra.size=0
                elif kind=='missing':f.pop('web/app.js')
                else:f['config.json']=b'{}'
                with self.assertRaises(Error):unpack_release(blob(f,extra),self.root/kind,VERSION)
                self.assertFalse((self.root/kind).exists())
        self.assertFalse((self.root.parent/'escape').exists())

    def test_manifest_tampering_and_version_mismatch_rejected(self):
        f=files();f['panel/core.py']+=b'\n# changed'
        with self.assertRaises(Error):unpack_release(blob(f),self.root/'candidate',VERSION)
        with self.assertRaises(Error):unpack_release(blob(files()),self.root/'candidate','9.9.9')

    def test_checksum_failure_does_not_extract(self):
        info={'latest':VERSION,'assets':{ARCHIVE:'archive',ARCHIVE+'.sha256':'sum'}}
        with patch('panel.releases.download',side_effect=[blob(files()),('0'*64+'  '+ARCHIVE).encode()]):
            with self.assertRaises(Error):fetch_release(info,self.root/'candidate')
        self.assertFalse((self.root/'candidate').exists())

    def metadata(self,version='9.0.0'):
        return {'tag_name':'v'+version,'draft':False,'prerelease':False,'assets':[{'name':name,'browser_download_url':'https://github.com/'+REPOSITORY+'/releases/download/v'+version+'/'+name} for name in [ARCHIVE,ARCHIVE+'.sha256']]}

    def test_latest_uses_fixed_assets_and_does_not_downgrade(self):
        with patch('panel.releases.download',return_value=json.dumps(self.metadata('0.1.0')).encode()):self.assertFalse(release_info()['available'])
        m=self.metadata();m['assets'][0]['browser_download_url']='https://other.example.test/code'
        with patch('panel.releases.download',return_value=json.dumps(m).encode()):
            with self.assertRaises(Error):release_info()

    def prepare_root(self):
        state=self.root/'opt/etc/tailscale-panel';state.mkdir(parents=True)
        target=self.root/'opt/share/tailscale-panel';target.mkdir(parents=True)
        (target/'old-code').write_text('previous')
        write_json(state/'config.json',{'version':'0.9.0','port':8192,'tun':'opkgtun3','custom':{'preserve':True}})
        write_json(state/'manifest.json',{'version':'0.9.0','created':['sentinel']})
        write_json(state/'auth.json',{'username':'test-owner','password_hash':'test-sentinel'})
        write_json(state/'devices.json',{'test':'private-notes'})
        keys=self.root/'opt/var/tailscaled.state';keys.parent.mkdir(parents=True);keys.write_bytes(b'identity-sentinel')
        task=PanelUpdater(state);task.root.mkdir()
        f=files();m=unpack_release(blob(f),task.root/'candidate',VERSION)
        write_json(task.journal,{'id':'test','token':'test-token','state':'prepared','version':VERSION,'from_version':'0.9.0','files':m['files'],'started_at':time.time()})
        return state,target,task,keys

    def test_panel_swap_preserves_account_network_keys_and_adds_command(self):
        state,target,task,keys=self.prepare_root();auth=(state/'auth.json').read_bytes();calls=[]
        result=apply_staged(state,'test-token',str(self.root),calls.append,lambda *args:True)
        self.assertEqual(result['state'],'done');self.assertEqual(calls,['stop','start'])
        self.assertEqual((state/'auth.json').read_bytes(),auth);self.assertEqual(keys.read_bytes(),b'identity-sentinel')
        self.assertEqual(read_json(state/'config.json')['custom'],{'preserve':True})
        self.assertEqual(read_json(state/'devices.json'),{'test':'private-notes'})
        self.assertTrue((self.root/'opt/bin/tailscalekeen').exists());self.assertTrue((target/'panel/server.py').exists())
        self.assertFalse(task.active());self.assertNotIn('token',result);self.assertNotIn('files',result)

    def test_bad_health_rolls_back_code_launchers_and_config(self):
        state,target,task,keys=self.prepare_root();config=(state/'config.json').read_bytes();calls=[]
        result=apply_staged(state,'test-token',str(self.root),calls.append,lambda port,version,configured:version=='0.9.0')
        self.assertEqual(result['state'],'rolled_back');self.assertEqual((target/'old-code').read_text(),'previous')
        self.assertEqual((state/'config.json').read_bytes(),config);self.assertEqual(keys.read_bytes(),b'identity-sentinel')
        self.assertFalse((self.root/'opt/bin/tailscalekeen').exists());self.assertEqual(calls,['stop','start','stop','start'])

    def test_staged_tampering_stops_before_service(self):
        state,target,task,keys=self.prepare_root();(task.root/'candidate/panel/core.py').write_text('tampered')
        calls=[]
        with self.assertRaises(Error):apply_staged(state,'test-token',str(self.root),calls.append,lambda *args:True)
        self.assertEqual(calls,[]);self.assertFalse(task.active());self.assertEqual((target/'old-code').read_text(),'previous')

    def test_failed_candidate_rename_restores_previous_directory(self):
        import os
        state,target,task,keys=self.prepare_root();original=os.rename;calls=[]
        def rename(source,destination):
            if pathlib.Path(source).name=='.tailscale-panel-new':raise OSError('simulated storage error')
            return original(source,destination)
        with patch('panel.panel_update.os.rename',side_effect=rename):
            result=apply_staged(state,'test-token',str(self.root),calls.append,lambda *args:True)
        self.assertEqual(result['state'],'rolled_back')
        self.assertEqual((target/'old-code').read_text(),'previous')
        self.assertEqual(read_json(state/'config.json')['version'],'0.9.0')

    def test_history_uses_time_and_caps_finished_jobs(self):
        jobs=Jobs(self.root)
        for n in range(110):write_json(jobs.path/(format(110-n,'024x')+'.json'),{'id':n,'started_at':n,'state':'done'})
        self.assertEqual(jobs.list()[0]['id'],109);jobs.prune();self.assertEqual(len(list(jobs.path.glob('*.json'))),100)


if __name__=='__main__':unittest.main()
