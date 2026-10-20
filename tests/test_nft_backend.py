import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import nft_backend
import server
from test_controller import database

class NftBackendTests(unittest.TestCase):
    def test_failed_transaction_restores_persistent_firewall_include(self):
        db,a,b=database()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'firewall.nft';path.write_text('previous configuration\n')
            def run(args,**kwargs):
                listing={'nftables':[{'set':{'name':server.set_name(ident)}} for ident in (a,b)]}
                return subprocess.CompletedProcess(args,0,json.dumps(listing),'')
            with patch.object(nft_backend,'RULES',path),patch.object(server,'run',side_effect=run),patch.object(nft_backend,'nft',side_effect=ValueError('Rejected transaction')),self.assertRaises(ValueError):
                nft_backend.firewall(db)
            self.assertEqual(path.read_text(),'previous configuration\n')

    def test_live_firewall_update_does_not_flush_other_lease_sets(self):
        db,a,b=database()
        listing={'nftables':[{'set':{'name':server.set_name(ident)}} for ident in (a,b)]}
        with tempfile.TemporaryDirectory() as directory,patch.object(nft_backend,'RULES',Path(directory)/'firewall.nft'),patch.object(server,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(listing),'')),patch.object(nft_backend,'nft') as transaction,patch.object(server,'service_operation') as reload:
            nft_backend.firewall(db)
            self.assertEqual(transaction.call_count,1)
            commands=transaction.call_args.args[0]
            self.assertNotIn('flush set',commands);self.assertNotIn('flush table',commands)
            self.assertNotIn('delete set',commands)
            self.assertIn('update @'+server.set_name(a)+' { ip saddr timeout 10s }',commands)
            self.assertIn('update @'+server.set_name(a)+' { ip daddr timeout 10s }',commands)
            reload.assert_not_called()

    def test_inactive_database_does_not_open_ports(self):
        db,a,b=database();db['activated']=False
        text=nft_backend.render(db)
        self.assertNotIn(' dport ',text);self.assertNotIn(' dnat ip ',text);self.assertNotIn(server.set_name(a),text)
        self.assertIn('chain knock_control_input',text)
