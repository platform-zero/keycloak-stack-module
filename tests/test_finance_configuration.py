#!/usr/bin/env python3
"""SOURCE ONLY: actual Bash producer with explicit native-admin command double."""
import json,os,pathlib,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
def uid(n):return f'{n:08x}-1111-4111-8111-000000000000'
class FinanceConfiguration(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.path=pathlib.Path(self.tmp.name)/'state.json'
  self.state={'argv':[],'humans':{uid(i):{'id':uid(i),'enabled':True,'emailVerified':True,'requiredActions':[]} for i in [1,2]},'groups':[{'id':uid(101),'name':'finance-owner','path':'/finance-owner'},{'id':uid(102),'name':'finance-users','path':'/finance-users'}],'members':{},'clients':[{'id':uid(200),'clientId':'realm-management'}],'mappings':[]}
  self.env=dict(os.environ,P0_FINANCE_DOUBLE_STATE=str(self.path),DOMAIN='source.invalid',REALM='webservices',KC=str(ROOT/'tests/finance_kcadm_double.py'),FIREFLY_OWNER_SUBJECT=uid(1),FIREFLY_USER_SUBJECTS=uid(2),FIREFLY_OAUTH_SECRET='A'*40,FIREFLY_IMPORTER_OAUTH_SECRET='B'*40,FIREFLY_IDENTITY_CLIENT_SECRET='C'*40)
 def call(self):
  self.path.write_text(json.dumps(self.state))
  p=subprocess.run(['bash','-c','set -euo pipefail; source "$1"; configure_finance_identity','source-double',str(ROOT/'stack.config/keycloak/configure-finance.sh')],env=self.env,capture_output=True,text=True,timeout=15)
  self.state=json.loads(self.path.read_text());return p
 def test_explicit_humans_narrow_clients_and_no_secret_argv(self):
  p=self.call();self.assertEqual(p.returncode,0,p.stderr)
  clients={c['clientId']:c for c in self.state['clients']};self.assertEqual(set(clients),{'realm-management','firefly-sso','firefly-importer-sso','firefly-identity-reader'})
  for name in ['firefly-sso','firefly-importer-sso']:
   c=clients[name];self.assertTrue(c['standardFlowEnabled']);self.assertFalse(c['directAccessGrantsEnabled']);self.assertFalse(c['serviceAccountsEnabled']);self.assertFalse(c['implicitFlowEnabled']);self.assertFalse(c['fullScopeAllowed']);self.assertEqual(c['optionalClientScopes'],[])
   self.assertEqual(c['attributes']['pkce.code.challenge.method'],'S256');self.assertEqual(c['protocolMappers'][0]['config']['full.path'],'true')
  reader=clients['firefly-identity-reader'];self.assertTrue(reader['serviceAccountsEnabled']);self.assertFalse(reader['standardFlowEnabled']);self.assertFalse(reader['directAccessGrantsEnabled'])
  self.assertEqual(self.state['members'][uid(101)],[uid(1)]);self.assertEqual(self.state['members'][uid(102)],[uid(2)])
  self.assertEqual(len(self.state['mappings']),2)
  for mapping in self.state['mappings']:self.assertEqual({x['name'] for x in mapping['roles']},{'view-users','query-users','query-groups'})
  argv=json.dumps(self.state['argv'])
  for value in ['A'*40,'B'*40,'C'*40]:self.assertNotIn(value,argv+p.stdout+p.stderr)
 def test_realm_declares_empty_nondefault_finance_groups(self):
  realm=json.loads((ROOT/'stack.config/keycloak/realm/webservices-realm.json.template').read_text())
  groups={g['name']:g for g in realm['groups']}
  for name in ['finance-owner','finance-users']:
   self.assertIn(name,groups);self.assertFalse(groups[name].get('users'));self.assertNotIn('/'+name,realm.get('defaultGroups',[]))
 def test_idempotent_same_inputs(self):
  self.assertEqual(self.call().returncode,0);self.assertEqual(self.call().returncode,0);self.assertEqual(len(self.state['clients']),4)
 def test_disabled_unverified_service_account_and_required_action_refused(self):
  for patch in [{'enabled':False},{'emailVerified':False},{'serviceAccountClientId':'synthetic-service'},{'requiredActions':['VERIFY_EMAIL']}]:
   with self.subTest(patch=patch):
    self.state['humans'][uid(1)]={'id':uid(1),'enabled':True,'emailVerified':True,'requiredActions':[],**patch};self.assertNotEqual(self.call().returncode,0)
 def test_native_admin_failure_propagates(self):
  self.state['failRoute']='users/'+uid(1);self.assertNotEqual(self.call().returncode,0);self.assertEqual(len(self.state['clients']),1)
 def test_ambiguous_existing_owner_refused(self):
  self.state['members'][uid(101)]=[uid(1),uid(2)];self.assertNotEqual(self.call().returncode,0)
 def test_foreign_client_not_adopted(self):
  c={'id':uid(201),'clientId':'firefly-sso','attributes':{'managed-by':'foreign'}};self.state['clients'].append(c)
  self.assertNotEqual(self.call().returncode,0);self.assertEqual(next(x for x in self.state['clients'] if x['id']==uid(201)),c)
 def test_foreign_group_path_refused(self):
  self.state['groups'][0]['path']='/foreign/finance-owner';self.assertNotEqual(self.call().returncode,0)
 def test_unexpected_reader_role_refused(self):
  self.state['effectiveRoles']=['view-users','realm-admin'];self.assertNotEqual(self.call().returncode,0)
 def test_distinct_secrets_required(self):
  self.env['FIREFLY_IMPORTER_OAUTH_SECRET']=self.env['FIREFLY_OAUTH_SECRET'];self.assertNotEqual(self.call().returncode,0);self.assertEqual(self.state['argv'],[])
 def test_mutable_identifier_not_subject(self):
  self.env['FIREFLY_OWNER_SUBJECT']='mutable@example.invalid';self.assertNotEqual(self.call().returncode,0);self.assertEqual(self.state['argv'],[])
 def test_owner_cannot_be_nonowner_enrollment(self):
  self.env['FIREFLY_USER_SUBJECTS']=uid(1);self.assertNotEqual(self.call().returncode,0)
 def test_fresh_groups_created(self):
  self.state['groups']=[];self.assertEqual(self.call().returncode,0);self.assertEqual(len(self.state['groups']),2)
if __name__=='__main__':unittest.main(verbosity=2)
