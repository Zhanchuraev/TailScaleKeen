import json, os, pathlib, shutil, subprocess, tempfile, time, unittest
from types import SimpleNamespace
from unittest.mock import patch
from panel import legacy_policy as legacy
from panel.core import Error, read_json, write_json

TEXT = """policy, name = Policy0, description = Default:
 mark: a
 table4: 4000
policy, name = Policy7, description = Sample:
 mark: 0x1234
 table4: 7300
 route4:
   route:
     metric: 1000
policy, name = Policy8, description = Other:
 mark: 90
 table4: 8000
"""
POLICY = """import json, urllib.request
CFG={'native_policy':'Policy7'}
def run(args):
 return RESULT
def sync():
 p=json.load(urllib.request.urlopen('http://localhost:79/rci/show/ip/policy',timeout=8))[CFG['native_policy']]
 assert p['description']=='Sample'
 return p['table4']
"""
INIT = '''#!/bin/sh
case "$1" in
 start|restart)
  echo start
 ;;
 stop)
  echo stop
 ;;
esac
'''


class PolicyMetadataTests(unittest.TestCase):
    def test_selects_named_policy_not_first_table(self):
        self.assertEqual(legacy.policy_metadata(TEXT, "Policy7"),
                         {"description":"Sample", "table4":7300, "mark":0x1234})

    def test_plain_hex_and_terminal_escape_sequences(self):
        self.assertEqual(legacy.policy_metadata("\x1b[K" + TEXT.replace("0x1234","abcd"), "Policy7")["mark"], 0xabcd)

    def test_rejects_missing_duplicate_and_invalid_metadata(self):
        for text, name in [(TEXT,"Missing"), (TEXT+TEXT,"Policy7"),
                           (TEXT.replace("table4: 7300","table4: 0"),"Policy7"),
                           (TEXT.replace("mark: 0x1234","mark: 100000000"),"Policy7"),
                           (TEXT.replace("table4: 7300","table4: 7300\n table4: 7301"),"Policy7"),
                           (TEXT,"Policy7\nother"), (TEXT,None)]:
            with self.subTest(name=name,text=text):
                with self.assertRaises(ValueError):legacy.policy_metadata(text,name)


class LegacyMigrationTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=pathlib.Path(tmp.name);self.state=self.root/'opt/etc/tailscale-panel'
        self.policy=self.root/legacy.POLICY.lstrip('/');self.init=self.root/legacy.INIT.lstrip('/')
        for p,blob in [(self.policy,POLICY),(self.init,INIT)]:
            p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(blob.encode())
        self.config=self.root/legacy.CONFIG.lstrip('/');write_json(self.config,{'native_policy':'Policy7','unchanged':'keep'})
        self.config_before=self.config.read_bytes();self.calls=[]
        self.runner=SimpleNamespace(run=lambda args,**kw:SimpleNamespace(stdout=TEXT,returncode=0))
        self.migration=legacy.LegacyPolicy(self.state,self.root,self.runner,self.control)
        replacements=patch.multiple(legacy,OLD_POLICY=legacy.digest(self.policy.read_bytes()),OLD_INIT=legacy.digest(self.init.read_bytes()))
        replacements.start();self.addCleanup(replacements.stop)

    def control(self, action):self.calls.append(action)

    def test_migrates_standalone_helper_preserving_router_configuration(self):
        old=self.policy.read_bytes();result=self.migration.migrate()
        self.assertEqual(result['state'],'migrated');self.assertEqual(self.calls,['stop','start'])
        self.assertEqual(self.config.read_bytes(),self.config_before)
        self.assertEqual((self.migration.directory/'policy').read_bytes(),old)
        self.assertNotIn(legacy.NEEDLE,self.policy.read_text())
        namespace={'RESULT':SimpleNamespace(stdout=TEXT)};exec(compile(self.policy.read_text(),'policy.py','exec'),namespace)
        self.assertEqual(namespace['sync'](),7300)
        self.assertIn('"$0" stop',self.init.read_text());self.assertNotIn('start|restart)',self.init.read_text())
        if shutil.which('sh'):subprocess.run(['sh','-n',str(self.init)],check=True)
        self.assertEqual(self.migration.migrate()['state'],'already_compatible');self.assertEqual(self.calls,['stop','start'])

    def test_unknown_script_and_clean_install_are_preserved_without_commands(self):
        self.policy.write_text(POLICY+'\n# administrator edit\n')
        self.assertEqual(self.migration.migrate()['state'],'unrecognized_preserved');self.assertEqual(self.calls,[])
        self.policy.unlink();self.assertEqual(self.migration.migrate()['state'],'not_applicable')

    def test_native_metadata_failure_changes_nothing(self):
        self.runner.run=lambda *a,**kw:SimpleNamespace(stdout=TEXT.replace('Policy7','Policy9'))
        with self.assertRaises(ValueError):self.migration.migrate()
        self.assertEqual(self.policy.read_text(),POLICY);self.assertEqual(self.init.read_text(),INIT);self.assertEqual(self.calls,[])

    def test_failed_start_restores_both_scripts_and_restarts_previous_service(self):
        def fail_once(action):
            self.calls.append(action)
            if self.calls==['stop','start']:raise RuntimeError('new service failed')
        self.migration.control=fail_once
        with self.assertRaises(RuntimeError):self.migration.migrate()
        self.assertEqual(self.policy.read_text(),POLICY);self.assertEqual(self.init.read_text(),INIT)
        self.assertEqual(self.calls,['stop','start','stop','start'])
        self.assertEqual(read_json(self.migration.journal)['state'],'rolled_back')

    def test_interrupted_two_file_migration_recovers_before_retrying(self):
        self.migration.migrate();record=read_json(self.migration.journal);record['state']='pending';write_json(self.migration.journal,record)
        self.init.write_bytes(INIT.encode());self.calls.clear()
        self.assertEqual(self.migration.migrate()['state'],'migrated')
        self.assertEqual(self.calls,['stop','start','stop','start'])

    def test_recovery_never_overwrites_concurrent_administrator_edit(self):
        self.migration.migrate();record=read_json(self.migration.journal);record['state']='pending';write_json(self.migration.journal,record)
        self.init.write_text('# administrator changed this\n');self.calls.clear()
        with self.assertRaises(Error):self.migration.migrate()
        self.assertEqual(self.init.read_text(),'# administrator changed this\n');self.assertEqual(self.calls,[])

    def test_recognizes_already_repaired_pair_without_restart(self):
        with patch.multiple(legacy,FIXED_POLICY=legacy.digest(self.policy.read_bytes()),FIXED_INIT=legacy.digest(self.init.read_bytes())):
            self.assertEqual(self.migration.migrate()['state'],'already_compatible')
        self.assertEqual(self.calls,[])

    def test_no_start_mode_defers_migration(self):
        self.assertEqual(legacy.migrate(self.state,self.root,self.runner,live=False)['state'],'deferred')
        self.assertEqual(self.policy.read_text(),POLICY);self.assertEqual(self.init.read_text(),INIT)

    def test_live_acceptance_requires_fresh_status_and_correct_process(self):
        runtime=self.root/'tmp';runtime.mkdir();proc=self.root/'proc/123';proc.mkdir(parents=True)
        (runtime/'tailscale-policy.pid').write_text('123')
        (proc/'cmdline').write_bytes(b'/opt/bin/python3\0'+legacy.POLICY.encode()+b'\0')
        status=runtime/'tailscale-policy.status';write_json(status,{'native_table':7300,'native_mark':0x1234})
        metadata=legacy.policy_metadata(TEXT,'Policy7')
        self.migration.verify_started(time.time()-1,metadata,timeout=0)
        with self.assertRaises(Error):self.migration.verify_started(time.time()+1,metadata,timeout=0)
        (runtime/'tailscale-policy.last-error').write_text('new service error')
        with self.assertRaises(Error):self.migration.verify_started(time.time()-1,metadata,timeout=0)
        (runtime/'tailscale-policy.last-error').unlink()
        (proc/'cmdline').write_bytes(b'other-program\0')
        with self.assertRaises(Error):self.migration.verify_started(time.time()-1,metadata,timeout=0)
