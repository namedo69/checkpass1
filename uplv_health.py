"""Small HTTP health server for Render Web Services; no game data exposed."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import secrets


def start_health(host, port, shutdown, version, token='', logs=None, status=None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path.split('?', 1)[0] == '/api/logs':
                supplied = self.headers.get('Authorization', '')
                if not token or not secrets.compare_digest(supplied, 'Bearer ' + token):
                    self.send_error(403)
                    return
                details = status() if status else {}
                body = json.dumps({'ok': True, 'satellite_id': details.get('id'), 'logs': logs() if logs else []}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path.split('?', 1)[0] not in ('/', '/healthz'):
                self.send_error(404)
                return
            details = status() if status else {}
            ready = not shutdown.is_set() and details.get('worker_loop_ok', True)
            body = json.dumps({'ok': ready, 'role': 'satellite', 'service_type': 'uplv',
                               'version': version, **details}).encode()
            self.send_response(200 if ready else 503)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name='uplv-health', daemon=True).start()
    return server
