#!/usr/bin/python3
"""Grant the installing user immediate access to the client socket."""
import json
from pathlib import Path
import subprocess
import time

socket = Path('/run/autobricks-pki-client/client.sock')
for _ in range(100):
    if socket.is_socket():
        break
    time.sleep(0.1)
else:
    raise SystemExit('client socket did not become ready')
uid = json.loads(Path('/etc/autobricks-pki-client/ownership.json').read_text()).get('installer_uid')
if uid is not None:
    if not isinstance(uid, int) or uid <= 0:
        raise SystemExit('invalid installer UID')
    subprocess.run(['setfacl', '-m', f'u:{uid}:rwx', str(socket.parent)], check=True)
    subprocess.run(['setfacl', '-m', f'u:{uid}:rw', str(socket)], check=True)
