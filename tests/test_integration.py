import pathlib,subprocess,tempfile,unittest
from panel.core import Error,write_json,read_json
from panel.integration import Integration

class Runner:
    def __init__(self):self.calls=[];self.rules='';self.guard=True
    def run(self,args,**kwargs):
        self.calls.append(args);out='';code=0
        if args==['ip','-4','rule','show']:out=self.rules
        elif args==['ip','-4','route','show','table','main']:out='192.168.10.0/24 dev br0 scope link\n'
        elif args==['ip','-4','route','show','table','52']:out='100.64.250.2 dev opkgtun0\n192.168.10.0/24 dev opkgtun0\n192.168.20.0/24 dev opkgtun0\n0.0.0.0/1 dev opkgtun0\n128.0.0.0/1 dev opkgtun0\ndefault dev opkgtun0\n'
        elif '-C' in args:code=1
        elif args[-2:]==['-S','FORWARD'] and self.guard:out='-A FORWARD -j TSP_EXIT_FWD\n-A FORWARD -j OTHER\n'
        return subprocess.CompletedProcess(args,code,out,'')

SNAP={'backend_state':'Running','self':{'TailscaleIPs':['100.64.250.1']},'prefs':{'RouteAll':True},'peers':[{'TailscaleIPs':['100.64.250.2'],'AllowedIPs':['192.168.10.0/24','192.168.20.0/24','0.0.0.0/0']}]}

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.state=pathlib.Path(self.tmp.name);self.runner=Runner();self.i=Integration(self.state,self.runner,root=self.state)
        write_json(self.state/'config.json',{'managed_policy_sync':True})
    def test_adopted_existing_helpers_are_passive(self):
        write_json(self.state/'config.json',{'managed_policy_sync':False})
        self.assertEqual(self.i.sync(SNAP),{'managed':False});self.assertEqual(self.runner.calls,[])
    def test_only_peer_subnet_routes_excluding_connected_and_exit_defaults(self):
        self.assertEqual(self.i.prefixes(SNAP,4),['100.64.250.2/32','192.168.20.0/24'])
        result=self.i.sync(SNAP);self.assertTrue(result['active'])
        rules=read_json(self.i.record)['rules']
        self.assertFalse(any('default' in r or '0.0.0.0/1' in r for r in rules))
        self.assertIn(['iptables','-w','-t','filter','-I','FORWARD','2','-j','TSK_FORWARD'],self.runner.calls)
    def test_foreign_priority_conflict_fails_before_mutation(self):
        self.runner.rules='69: from all lookup 123\n'
        with self.assertRaises(Error):self.i.sync(SNAP)
        self.assertFalse(self.i.record.exists());self.assertFalse(any('add' in a or '-N' in a for a in self.runner.calls))
    def test_cleanup_deletes_only_own_specific_rules_and_chains(self):
        self.i.sync(SNAP);self.runner.calls=[];self.i.remove()
        self.assertTrue(all('flush' not in a for a in self.runner.calls))
        self.assertFalse(any('-F' in a and a[-1] in ['INPUT','FORWARD','POSTROUTING'] for a in self.runner.calls))
        self.assertTrue(any(a[:4]==['ip','-4','rule','del'] for a in self.runner.calls))
        self.assertFalse(self.i.record.exists())
    def test_hook_preserves_foreign_content(self):
        self.i.install_hook();self.assertIn('integration-sync',(self.state/'opt/etc/ndm/netfilter.d/96-tailscale-panel.sh').read_text())
        (self.state/'opt/etc/ndm/netfilter.d/96-tailscale-panel.sh').write_text('foreign')
        with self.assertRaises(Error):self.i.install_hook()
    def test_host_prefix_rendered_without_mask_is_idempotent(self):
        self.i.sync(SNAP)
        self.runner.rules='69: from all fwmark 0x80000/0xff0000 lookup main\n70: from all to 100.64.250.2 lookup 52\n70: from all to 192.168.20.0/24 lookup 52\n'
        self.runner.calls=[];self.i.sync(SNAP)
        self.assertFalse(any(a[:4]==['ip','-4','rule','add'] for a in self.runner.calls))
