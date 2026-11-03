"""Unprivileged control-channel smoke test; never injects a packet."""
import json,os,pathlib,socket,subprocess,tempfile,unittest
class HelperControlTests(unittest.TestCase):
 def test_private_session_rejects_unsafe_operations_and_exits(self):
  exe=pathlib.Path(__file__).resolve().parents[1]/'dist/sni-helper'/('sni-spoof-helper.exe' if os.name=='nt' else 'sni-spoof-helper')
  if not exe.exists():self.skipTest('native helper not built on this runner')
  self.assertIn('sni-spoof-helper 1',subprocess.check_output([str(exe),'--version'],text=True))
  with tempfile.TemporaryDirectory() as directory,socket.socket() as server:
   server.bind(('127.0.0.1',0));server.listen();server.settimeout(5)
   path=pathlib.Path(directory)/'session.json';path.write_text(json.dumps({'port':server.getsockname()[1],'token':'fixture-token'}));path.chmod(0o600)
   proc=subprocess.Popen([str(exe),'--broker',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
   try:
    peer,_=server.accept()
    with peer,peer.makefile('rw') as channel:
     self.assertEqual(json.loads(channel.readline())['token'],'fixture-token')
     for request in [{'cmd':'unknown'},{'cmd':'start','id':'test','listen':'0.0.0.0:40443','connect':'104.21.56.43:443'},{'cmd':'start','id':'test','listen':'127.0.0.1:40443','connect':'91.107.177.38:443'}]:
      channel.write(json.dumps(request)+'\n');channel.flush();self.assertFalse(json.loads(channel.readline())['ok'])
     channel.write('{"cmd":"diagnostics","requestId":42}\n');channel.flush();diagnostics=json.loads(channel.readline());self.assertEqual(diagnostics['requestId'],42);self.assertIsInstance(diagnostics['lines'],list)
     channel.write('{"cmd":"shutdown"}\n');channel.flush();self.assertTrue(json.loads(channel.readline())['ok'])
    self.assertEqual(proc.wait(timeout=5),0)
   finally:
    if proc.poll() is None:proc.kill();proc.wait()
    proc.stderr.close()
if __name__=='__main__':unittest.main()
