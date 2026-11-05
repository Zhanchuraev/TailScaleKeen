"""Clean-install routing before NDM policy rules; never adopt foreign helpers."""
import ipaddress,pathlib,re,shlex
from .core import Error,read_json,write_json
from .routing import route_rows,rule_rows

HOOK='/opt/etc/ndm/netfilter.d/96-tailscale-panel.sh'
SIGNATURE='# TailScaleKeen managed integration'
CHAINS={'filter':['TSK_INPUT','TSK_FORWARD'],'nat':['TSK_SNAT']}

class Integration:
    def __init__(self,state,runner,tun='opkgtun0',root='/'):
        if not re.fullmatch(r'opkgtun(?:[0-9]|1[0-5])',tun):raise Error('Неизвестный TUN интеграции')
        self.state=pathlib.Path(state);self.runner=runner;self.tun=tun;self.root=pathlib.Path(root)
        self.record=self.state/'routing-integration.json'

    def call(self,args,check=True):
        return self.runner.run(args,check=check,timeout=15)

    def install_hook(self):
        p=self.root/HOOK.lstrip('/')
        text='#!/bin/sh\n'+SIGNATURE+'\n/opt/bin/tailscalekeen integration-sync >/dev/null 2>&1\n'
        if p.exists() and p.read_text()!=text:raise Error('Существующий netfilter hook принадлежит другой интеграции')
        p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);p.chmod(0o755)

    def prefixes(self,snapshot,family):
        allowed=set()
        for peer in [snapshot.get('self',{}),*snapshot.get('peers',[])]:
            values=list(peer.get('TailscaleIPs') or [])
            if snapshot.get('prefs',{}).get('RouteAll'):
                values+=list(peer.get('PrimaryRoutes') or [])+list(peer.get('AllowedIPs') or [])
            for value in values:
                try:
                    net=ipaddress.ip_network(value,strict=False)
                    if net.version==family and net.prefixlen:allowed.add(net)
                except ValueError:continue
        connected=[]
        for row in route_rows(self.call(['ip','-'+str(family),'route','show','table','main'],False).stdout):
            if row.get('dev')!=self.tun and row.get('dev') and not row.get('gateway') and row.get('dst')!='default':
                try:connected.append(ipaddress.ip_network(row['dst'],strict=False))
                except ValueError:pass
        result=set()
        for row in route_rows(self.call(['ip','-'+str(family),'route','show','table','52'],False).stdout):
            if row.get('dev')!=self.tun or row.get('type')!='unicast':continue
            try:net=ipaddress.ip_network(row['dst'],strict=False)
            except ValueError:continue
            if net.version!=family or not net.prefixlen:continue
            # Never promote exit defaults/split defaults ahead of native WAN policies.
            if net not in allowed and not (family==4 and net.subnet_of(ipaddress.ip_network('100.64.0.0/10'))):continue
            if any(net.overlaps(n) for n in connected if n.version==family):continue
            result.add(str(net))
        if len(result)>256:raise Error('Слишком много маршрутов для автоматической интеграции')
        return sorted(result)

    def rules(self,family,prefixes):
        base=['ip','-'+str(family),'rule']
        return [[*base,'add','pref','69','fwmark','0x80000/0xff0000','lookup','main'],
                *[[*base,'add','pref','70','to',str(ipaddress.ip_network(net)),'lookup','52'] for net in prefixes]]

    @staticmethod
    def contains(text,args):
        for line in text.splitlines():
            rows=rule_rows(line)
            if not rows or rows[0]['priority']!=int(args[5]):continue
            row=rows[0]
            if args[5]=='69':
                if row.get('fwmark')=='0x80000' and row.get('fwmask')=='0xff0000' and row.get('table')=='main':return True
            elif row.get('table')=='52':
                m=re.search(r'\bto (\S+)',line)
                try:
                    if m and ipaddress.ip_network(m[1])==ipaddress.ip_network(args[7]):return True
                except ValueError:pass
        return False

    @staticmethod
    def delete_rule(args):
        if args[:3] not in [['ip','-4','rule'],['ip','-6','rule']] or len(args)!=10 or args[3]!='add':raise Error('Повреждён список собственных правил')
        if args[4:6]==['pref','69']:
            if args[6:]!=['fwmark','0x80000/0xff0000','lookup','main']:raise Error('Неизвестное правило интеграции')
        elif args[4:7]==['pref','70','to']:
            ipaddress.ip_network(args[7])
            if args[8:]!=['lookup','52']:raise Error('Неизвестная таблица интеграции')
        else:raise Error('Неизвестный приоритет интеграции')
        return [*args[:3],'del',*args[4:]]

    def sync(self,snapshot):
        if not read_json(self.state/'config.json').get('managed_policy_sync'):return {'managed':False}
        if snapshot.get('backend_state')!='Running':return {'managed':True,'active':False}
        old=read_json(self.record).get('rules',[]);wanted=[]
        families=[4]+([6] if any(':' in x for x in (snapshot.get('self',{}).get('TailscaleIPs') or [])) else [])
        for family in families:
            existing=self.call(['ip','-'+str(family),'rule','show']).stdout
            for line in existing.splitlines():
                rows=rule_rows(line)
                if rows and rows[0]['priority'] in [69,70]:
                    row=rows[0]
                    is_owned=any(a[1]=='-'+str(family) and self.contains(line,a) for a in old)
                    if not is_owned:raise Error('Приоритеты ip rule 69/70 уже используются; интеграция остановлена без замены чужих правил')
            wanted+=self.rules(family,self.prefixes(snapshot,family))
        if not self.record.exists():
            for table,names in CHAINS.items():
                for name in names:
                    if '-N '+name in self.call(['iptables','-w','-t',table,'-S',name],False).stdout:
                        raise Error('Цепочка '+name+' уже существует без записи владельца; чужие правила не заменены')
        write_json(self.record,{'rules':wanted,'tun':self.tun})
        for args in old:
            if args not in wanted:self.call(self.delete_rule(args),False)
        for args in wanted:
            family=args[1];current=self.call(['ip',family,'rule','show']).stdout
            exists=self.contains(current,args)
            if not exists:self.call(args)
        for tool in ['iptables']+(['ip6tables'] if 6 in families else []):
            for table,names in CHAINS.items():
                for name in names:
                    prefix=[tool,'-w','-t',table]
                    self.call([*prefix,'-N',name],False)
            rules=[('filter','INPUT','TSK_INPUT',[]),('filter','TSK_INPUT',None,['-i',self.tun,'-j','ACCEPT']),
                   ('filter','FORWARD','TSK_FORWARD',[]),('filter','TSK_FORWARD',None,['-i',self.tun,'-j','ACCEPT']),
                   ('filter','TSK_FORWARD',None,['-o',self.tun,'-m','state','--state','RELATED,ESTABLISHED','-j','ACCEPT'])]
            private=['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'] if tool=='iptables' else ['fc00::/7']
            for net in private:
                rules += [('filter','TSK_FORWARD',None,['-s',net,'-o',self.tun,'-j','ACCEPT']),('nat','TSK_SNAT',None,['-s',net,'-o',self.tun,'-j','MASQUERADE'])]
            rules.append(('nat','POSTROUTING','TSK_SNAT',[]))
            for table,chain,jump,args in rules:
                if jump:args=['-j',jump]
                prefix=[tool,'-w','-t',table]
                if self.call([*prefix,'-C',chain,*args],False).returncode:
                    position=[]
                    if jump:
                        position=['1']
                        if chain=='FORWARD':
                            existing=[x for x in self.call([*prefix,'-S','FORWARD'],False).stdout.splitlines() if x.startswith('-A ')]
                            guard=next((i for i,line in enumerate(existing) if '-j TSP_EXIT_FWD' in line),None)
                            if guard is not None:position=[str(guard+2)]
                    self.call([*prefix,'-I' if jump else '-A',chain,*position,*args])
        return {'managed':True,'active':True,'prefixes':sum('to' in a for a in wanted)}

    def remove(self):
        record=read_json(self.record)
        if not record:return
        for args in record.get('rules',[]):self.call(self.delete_rule(args),False)
        for tool in ['iptables','ip6tables']:
            for table,names in CHAINS.items():
                prefix=[tool,'-w','-t',table]
                for parent,chain in [('INPUT','TSK_INPUT'),('FORWARD','TSK_FORWARD'),('POSTROUTING','TSK_SNAT')]:
                    if chain in names:self.call([*prefix,'-D',parent,'-j',chain],False)
                for name in names:
                    self.call([*prefix,'-F',name],False);self.call([*prefix,'-X',name],False)
        self.record.unlink(missing_ok=True)
