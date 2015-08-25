from distutils.core import setup
from ctypes import pythonapi
from socket import socket
import py2exe, sys, paramiko, ecdsa, ssl, ctypes, _ctypes, _thread

sys.argv.append('py2exe')

setup(
	options = {'py2exe': {'bundle_files': 1, 'optimize': 2, 'packages': ['paramiko', 'Crypto', 'ecdsa', 'ctypes'], 'includes': ['paramiko', 'Crypto', 'ecdsa', 'socket', 'ctypes', '_ctypes'], 'excludes':["pywin","tkinter","tcl"]}},
	console = [{'script': "meterssh.py"}],
	zipfile = None,
)