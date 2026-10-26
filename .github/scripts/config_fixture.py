"""Config Server simulado exclusivo del smoke; nunca contiene secretos reales."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        source = {"server.port": 8083, "spring.datasource.url": "${DB_URL}",
                  "spring.datasource.username": "${DB_USERNAME}", "spring.datasource.password": "${DB_PASSWORD}",
                  "logitrack.security.issuer": "https://issuer.test", "logitrack.security.token-ttl": "PT10M"}
        body = json.dumps({"name": "security-service", "profiles": ["prod"],
                           "propertySources": [{"name": "isolated-smoke", "source": source}]}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)
    def log_message(self, *_):
        pass

HTTPServer(("0.0.0.0", 8765), Handler).serve_forever()
