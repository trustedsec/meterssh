Tool Name: MeterSSH
Written by: David Kennedy
Company: TrustedSec
Website: https://www.trustedsec.com
Twitter: @TrustedSec, @HackingDave

MeterSSH is a way to take shellcode, inject it into memory then tunnel whatever port you want to over SSH to mask any type of communications as a normal SSH connection. The way it works is by injecting shellcode into memory, then wrapping a port spawned (meterpeter in this case) by the shellcode over SSH back to the attackers machine. Then connecting with meterpreter's listener to localhost will communicate through the SSH proxy, to the victim through the SSH tunnel. All communications are relayed through the SSH tunnel and not through the network.

### Features

1. Meterpreter over SSH
2. Ability to configure different IP's, addresses, etc. without the need to ever change the shellcode.
3. Monitor for the SSH connection and automatically spawn the shell

### Bugs and enhancements

For bug reports or enhancements, please open an issue here https://github.com/trustedsec/artillery/issues

### Usage

There are two files, monitor.py and meterssh.py. 

monitor.py - run this in order to listen for an SSH connection, it will poll for 8021 on localhost for an SSH tunnel then spawn Metasploit for you automatically to grab the shell.
meterssh.py - this is what you would deploy to the victim machine - note that most windows machines wont have Python installed, its recommended to compile Python with py2exe or pyinstaller.

Fields you need to edit inside meterssh.py

    user = "sshuser"
    # password for SSH
    password = "sshpw"
    # this is where your SSH server is running
    rhost = "192.168.1.1"
    # remote SSH port - this is the attackers SSH server
    port = "22"


user - this is the user account for the attackers SSH server (do not use root, does not need root)
password - this is the password for the attackers SSH server
rhost - this is the attackers SSH server IP address
port - this is the attackers SSH server port

Note that you DO NOT need to change the Metasploit shellcode, the Metasploit shellcode is simply an unmodified windows/meterpreter/bind_tcp that binds to port 8021. If you want to change this, just switch the shellcode out and change port 8021 inside the script to bind to whatever port you want to. You do not need to do this however unless you want to customize/modify.

### Supported platforms

- Windows

### License


Copyright 2014, MeterSSH by TrustedSec, LLC
All rights reserved. 

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of MeterSSH nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The above licensing was taken from the BSD licensing and is applied to MeterSSH as well.

Note that the MeterSSH is provided as is, and is a royalty free open-source application.

Feel free to modify, use, change, market, do whatever you want with it as long as you give the appropriate credit where credit is due (which means giving the authors the credit they deserve for writing it). Also note that by using this software, if you ever see the creator of SET in a bar, you should give him a hug and buy him a beer. Hug must last at least 5 seconds. Author holds the right to refuse the hug (most likely will never happen) or the beer (also most likely will never happen).

