import copy
import json
import subprocess
import unittest
from unittest.mock import patch
import common
import rules
import qr_codec
import server
from test_controller import database, ROOT


class RuleTests(unittest.TestCase):
    def test_invalid_rules_and_ambiguous_destinations_are_rejected(self):
        bad=[{'ports':['100-99']},{'ports':['0']},{'ports':['1-65536']},
             {'ports':['22; reboot']},{'ports':['22'],'interface':'wan" accept'},
             {'type':'dnat','ports':['2000-2010'],'dest_ip':'192.168.1.2','dest_port':22},
             {'type':'dnat','ports':['22'],'dest_ip':'224.0.0.1'},
             {'protocol':'icmp','ports':['22']},{'protocol':'icmp','icmp_type':'all'},
             {'type':'input','ports':['22'],'dest_ip':'192.168.1.2'}]
        for value in bad:
            with self.subTest(value=value),self.assertRaises(ValueError):rules.normalize(value)
        db,a,b=database()
        db['rules']={'one':{'type':'dnat','protocol':'tcp','ports':['2222'],'dest_ip':'192.168.1.2','dest_port':22},
                     'two':{'type':'dnat','protocol':'tcp','ports':['2220-2230'],'dest_ip':'192.168.1.3'}}
        with self.assertRaisesRegex(ValueError,'Conflicting'):rules.validate(db)

    def test_rule_list_policy_cannot_be_escalated_or_expose_transport(self):
        db,a,b=database()
        db['rules']={'ping':{'type':'input','protocol':'icmp'},'udp':{'type':'input','protocol':'udp','ports':['31000-31002']}}
        ident=server.issue(db,'Rules',[],[],rules=['ping'],allowed_rules=['ping','udp'])
        for port in (db['profiles'][a]['settings']['base'],):
            invalid=copy.deepcopy(db);invalid['rules']['unsafe']={'type':'input','protocol':'tcp','ports':[str(port)]}
            with self.assertRaises(ValueError):rules.validate(invalid)

    def test_rule_only_profile_qr_import_in_python_and_browser(self):
        db,a,b=database();db['rules']={'ping':{'type':'input','protocol':'icmp'}}
        ident=server.issue(db,'Phone',[],[],rules=['ping'])
        bundle=server.export_bundle(db,ident);url=qr_codec.enrollment_url(bundle)
        self.assertEqual(qr_codec.decode_enrollment(url)['settings']['rules'],['ping'])
        source=(ROOT/'extension/profile-codec.js').read_text()
        script='const m=await import("data:text/javascript;base64,"+Buffer.from('+json.dumps(source)+').toString("base64"));let s="";for await(const c of process.stdin)s+=c;process.stdout.write(JSON.stringify(m.decodeEnrollment(s)));'
        result=json.loads(subprocess.run(['node','--input-type=module','-e',script],input=url,text=True,capture_output=True,check=True).stdout)
        self.assertEqual(result['settings']['rules'],['ping']);self.assertEqual(result['settings']['ports'],[])
