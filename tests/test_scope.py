import importlib.util
import pathlib
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
spec=importlib.util.spec_from_file_location("recon",pathlib.Path(__file__).parents[1]/"Recon.py")
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)

class ScopeTests(unittest.TestCase):
    def test_redirect_never_reaches_destination(self):
        hits=[]
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/outside")
                self.end_headers()
            def log_message(self,*args): pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            scope=m.Scope({'127.0.0.1'})
            response=scope.request('GET',f'http://127.0.0.1:{server.server_port}/allowed',allow_redirects=True)
            self.assertEqual(response.status_code,302)
            self.assertEqual(hits,['/allowed'])
        finally: server.shutdown();server.server_close();thread.join()
    def test_url_parser(self):
        self.assertEqual(m._host_of('http://[::1]:8000/'),'::1')
        for value in ['http://allowed@outside/', 'file:///etc/passwd']:
            with self.assertRaises(m.ScopeError):m._host_of(value)
    def test_dns_answers_are_pinned_and_all_checked(self):
        scope=m.Scope({'10.0.0.0/24'})
        answer=[(2,1,6,'',('10.0.0.4',0))]
        with patch.object(m.socket,'getaddrinfo',return_value=answer),patch.object(m.requests.Session,'request') as request:
            scope.request('GET','https://target.test/path',verify=False)
            args,kwargs=request.call_args
            self.assertEqual(args[1],'https://10.0.0.4/path')
            self.assertTrue(kwargs['verify']);self.assertFalse(kwargs['allow_redirects'])
            self.assertEqual(kwargs['headers']['Host'],'target.test')
        answer.append((2,1,6,'',('192.0.2.1',0)))
        with patch.object(m.socket,'getaddrinfo',return_value=answer):
            with self.assertRaises(m.ScopeError):scope.request('GET','https://target.test/')
if __name__=='__main__':unittest.main()
