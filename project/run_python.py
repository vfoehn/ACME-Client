import sys
import subprocess
import time

args = sys.argv
record = args[5]

# Start subprocesses
dns_server_proc = subprocess.Popen(['python3', 'dns_server.py', record])
challenge_server_proc = subprocess.Popen(['python3', 'challenge_server.py', record])
shutdown_server_proc = subprocess.Popen(['python3', 'shutdown_server.py', record])
time.sleep(2)
acme_client_args = ['python3', 'acme_client.py'] + (args[1:])
print(acme_client_args)
acme_client_proc = subprocess.Popen(acme_client_args)

# End subprocesses
dns_server_proc.wait()
challenge_server_proc.wait()
shutdown_server_proc.wait()
acme_client_proc.wait()
