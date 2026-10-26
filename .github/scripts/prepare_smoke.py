import os
from pathlib import Path
import subprocess

root = Path(os.environ["SMOKE_FIXTURE_DIR"])
root.mkdir(parents=True, exist_ok=True)
subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(root/"private.pem")], check=True, capture_output=True)
subprocess.run(["openssl", "pkey", "-in", str(root/"private.pem"), "-pubout", "-out", str(root/"public.pem")], check=True, capture_output=True)
# Clave descartable de CI, legible por el UID del contenedor mediante bind de solo lectura.
(root/"private.pem").chmod(0o444)
(root/"public.pem").chmod(0o444)
