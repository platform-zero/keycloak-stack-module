#!/usr/bin/env python3
"""SOURCE TEST DOUBLE ONLY. Never used by deployment or OAuth/SSO tests."""
import json,os,sys
from pathlib import Path
p=Path(os.environ['P0_FINANCE_DOUBLE_STATE']);s=json.loads(p.read_text());a=sys.argv[1:];verb,route=a[:2]
s['argv'].append(a);p.write_text(json.dumps(s))
if s.get('failRoute')==route:sys.exit(7)
def uid(n):return f'{n:08x}-1111-4111-8111-000000000000'
def output(value):
 if '--fields' in a:
  fields=a[a.index('--fields')+1].split(',')
  def project(x):return {k:v for k,v in x.items() if k in fields}
  value=[project(x) for x in value] if isinstance(value,list) else project(value)
 p.write_text(json.dumps(s));print(json.dumps(value,indent=2));sys.exit(0)
def payload():return json.loads(Path(a[a.index('-f')+1]).read_text())
if verb=='get' and route=='groups':
 name=next(x.split('=',1)[1] for x in a if x.startswith('search='));output([g for g in s['groups'] if g['name']==name])
if verb=='create' and route=='groups':
 data=payload();s['groups'].append(dict(data,id=uid(100+len(s['groups'])),path='/'+data['name']));output({})
if verb=='get' and route.startswith('groups/') and route.endswith('/members'):
 group=route.split('/')[1];output([{'id':x} for x in s['members'].get(group,[])])
if verb=='update' and route.startswith('users/') and '/groups/' in route:
 _,subject,_,group=route.split('/');s['members'].setdefault(group,[])
 if subject not in s['members'][group]:s['members'][group].append(subject)
 output({})
if verb=='get' and route.startswith('users/') and '/role-mappings/' not in route:
 user=s['humans'].get(route.split('/')[1]);sys.exit(4) if user is None else output(user)
if verb=='get' and route=='clients':
 name=next(x.split('=',1)[1] for x in a if x.startswith('clientId='));output([c for c in s['clients'] if c['clientId']==name])
if verb=='create' and route=='clients':
 data=payload();s['clients'].append(dict(data,id=uid(200+len(s['clients']))));output({})
if verb=='update' and route.startswith('clients/'):
 identifier=route.split('/')[1];data=payload();index=next(i for i,c in enumerate(s['clients']) if c['id']==identifier)
 s['clients'][index]=dict(data,id=identifier);output({})
if verb=='get' and route.startswith('clients/') and route.endswith('/service-account-user'):output({'id':uid(300)})
if verb=='get' and '/roles/' in route:
 name=route.rsplit('/',1)[1];output({'id':uid(400+['view-users','query-users','query-groups'].index(name)),'name':name})
if verb=='create' and ('/role-mappings/' in route or '/scope-mappings/' in route):
 s['mappings'].append({'route':route,'roles':payload()});output({})
if verb=='get' and route.endswith('/composite'):output([{'name':x} for x in s.get('effectiveRoles',['view-users','query-users','query-groups'])])
print('unsupported source double command',file=sys.stderr);sys.exit(9)
