"""Imagen y MySQL reales con Config simulado; no representa cuatro servicios distribuidos."""
import base64
import json
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

def call(path, method="GET", data=None, token=None, expected=200):
    headers = {"Content-Type": "application/json"}
    if token: headers["Authorization"] = "Bearer " + token
    request = Request("http://127.0.0.1:8083"+path, method=method, headers=headers,
                      data=None if data is None else json.dumps(data).encode())
    try: response = urlopen(request, timeout=3)
    except HTTPError as failure: response = failure
    with response:
        assert response.status == expected, f"{method} {path}: estado HTTP inesperado"
        return json.load(response)

for attempt in range(60):
    try:
        assert call("/actuator/health") == {"status": "UP"}
        break
    except (OSError, AssertionError): time.sleep(2)
else: raise SystemExit("La imagen no inició con MySQL y Config de prueba")

call("/api/v1/auth/me", expected=401)
call("/api/v1/auth/login", "POST", {"username":"fixture-admin", "password":"invalid"}, expected=401)
login = call("/api/v1/auth/login", "POST", {"username":"fixture-admin", "password":"only-ci-admin-password"})
token = login["accessToken"]
assert call("/api/v1/auth/me", token=token)["roles"] == ["ADMIN"]
call("/api/v1/auth/me", token=token+"invalid", expected=401)
claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1]+"=="))
assert claims["iss"] == "https://issuer.test" and claims["exp"]-claims["iat"] == 600
client = call("/api/v1/auth/register", "POST", {"email":"fixture-client@example.test","username":"fixture-client","password":"Client-fixture-password"}, expected=201)
assert client["roles"] == ["CLIENTE"] and "passwordHash" not in client
client_token = call("/api/v1/auth/login", "POST", {"username":"fixture-client","password":"Client-fixture-password"})["accessToken"]
call("/api/v1/users/"+client["id"], token=client_token, expected=403)
call("/api/v1/auth/register", "POST", {"email":"blocked@example.test","password":"Client-fixture-password","roles":["ADMIN"]}, expected=403)
print("OK: imagen sin privilegios, MySQL/Flyway, configuración remota, RSA montada, login, perfil y rechazos 401/403")
