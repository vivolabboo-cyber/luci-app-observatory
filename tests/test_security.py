import importlib.util, tempfile, unittest, pathlib
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('collector',ROOT/'root/usr/lib/observatory/collector.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class SecurityTests(unittest.TestCase):
    def test_hostname_rejects_injection_and_address(self):
        for value in ['example.org; reboot','<script>','192.0.2.1','a'*254]:self.assertEqual(c.hostname(value),'')
        self.assertEqual(c.hostname('EXAMPLE.ORG.'),'example.org')
    def test_conntrack_and_unknown_route(self):
        row=c.parse_conntrack('ipv4 2 tcp 6 src=192.0.2.2 dst=198.51.100.2 sport=1234 dport=443 bytes=12 src=198.51.100.2 dst=192.0.2.2 bytes=34')
        self.assertEqual((row['up'],row['down']),(12,34))
        self.assertIsNone(c.parse_conntrack('invalid'))
        self.assertEqual(c.route_name([]),'unknown')
    def test_privacy_defaults_do_not_read_connection_sources(self):
        obj=c.Monitor.__new__(c.Monitor);obj.cfg={}
        with patch.object(c,'command') as cmd:
            self.assertEqual(obj.clash_connections(),[])
            obj.sample_dns();obj.sample_flows();cmd.assert_not_called()
        self.assertEqual(obj.flow_rows,[])
    def test_private_lan_api_target_is_rejected(self):
        obj=c.Monitor.__new__(c.Monitor);obj.cfg={'tachyon_enabled':True}
        payload='{"experimental":{"clash_api":{"external_controller":"192.0.2.1:9090","secret":"SYNTHETIC"}}}'
        with patch.object(c,'read',return_value=payload),patch.object(c.urllib.request,'build_opener') as opener:
            self.assertEqual(obj.clash_connections(),[]);opener.assert_not_called()
    def test_no_automatic_rpc_repair(self):
        obj=c.Monitor.__new__(c.Monitor);obj.last_rpc_check=0;obj.errors={}
        with patch.object(c,'command',return_value='') as cmd:
            obj.check_rpc_registration()
            self.assertTrue(all(call.args[0][0]=='ubus' for call in cmd.call_args_list))
    def test_api_redirect_is_rejected(self):
        with self.assertRaises(c.urllib.error.HTTPError):
            c.NoRedirect().redirect_request(c.urllib.request.Request('http://127.0.0.1:9090/'),None,302,'redirect',{},'https://example.org/')
    def test_invalid_interface_rejected_before_side_effects(self):
        with self.assertRaises(ValueError):c.Monitor({'interface':'br-lan; reboot'})
if __name__=='__main__':unittest.main()
