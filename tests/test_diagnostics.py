import importlib.util,pathlib,tempfile,unittest,json,time
p=pathlib.Path(__file__).resolve().parents[1]/'root/usr/lib/observatory/diagnostics.py'
spec=importlib.util.spec_from_file_location('diagnostics',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.d=m.Diagnostics(self.tmp.name)
 def tearDown(self):self.tmp.cleanup()
 def dns(self,text,t=100):self.d.dns('Nov 7 dnsmasq[1]: '+text,t,{'192.0.2.2':'a','192.0.2.3':'b'})
 def test_concurrent_dns_not_attributed_to_wrong_device(self):
  self.dns('1 192.0.2.2/123 query[A] example.com from 192.0.2.2')
  self.dns('2 192.0.2.3/124 query[A] example.com from 192.0.2.3')
  self.dns('1 192.0.2.2/123 reply example.com is 0.0.0.0')
  self.dns('2 192.0.2.3/124 reply example.com is 1.1.1.1')
  self.assertEqual([(r['device'],r['status']) for r in self.d.rows.values()],[('a','dns_sinkhole'),('b','dns_answer')])
 def test_nodata_not_error_and_unmatched_not_timeout(self):
  self.dns('3 192.0.2.2/1 query[AAAA] example.com from 192.0.2.2')
  self.dns('3 192.0.2.2/1 reply example.com is NODATA-IPv6')
  self.dns('4 192.0.2.2/1 query[A] silent.example from 192.0.2.2')
  self.d.snapshot(131,{})
  self.assertEqual([r['status'] for r in self.d.rows.values()],['dns_nodata','dns_unconfirmed'])
 def flow(self,up,down,t):
  self.d.observe_flows([dict(diag_id='api:one',device='a',domain='example.com',up=up,down=down,route='vpn',source='Tachyon',protocol='tcp')],t)
 def test_sustained_no_reply_then_recovery(self):
  self.flow(189,0,100);self.assertEqual(self.d.rows['api:one']['status'],'waiting')
  self.flow(189,0,114);self.assertEqual(self.d.rows['api:one']['status'],'waiting')
  self.flow(189,0,115);self.assertEqual(self.d.rows['api:one']['status'],'no_reply')
  self.flow(1000,2000,120);self.assertEqual(self.d.rows['api:one']['status'],'reply_seen')
 def test_closed_short_connection_is_not_failure(self):
  self.flow(100,0,100);self.d.observe_flows([],105);self.assertEqual(self.d.rows['api:one']['status'],'ended_unconfirmed')
 def test_bounds_and_device_filter(self):
  now=int(time.time())
  for i in range(m.MAX_ROWS+100):self.d.record(str(i),dict(device='a' if i%2 else 'b',last=now))
  self.d.snapshot(now,{})
  result=m.report({'runtime':self.tmp.name},{'device':'a'})
  self.assertLessEqual(len(self.d.rows),m.MAX_ROWS);self.assertEqual(self.d.dropped,100)
  self.assertTrue(all(r['device']=='a' for r in result['rows']))
  self.assertEqual(m.report({'runtime':self.tmp.name},{'device':''})['rows'],[])
if __name__=='__main__':unittest.main()
