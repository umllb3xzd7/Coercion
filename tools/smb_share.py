#!/usr/bin/env python3
import argparse
import sys
import logging

from impacket.examples import logger
from impacket import smbserver


def main():
	parser = argparse.ArgumentParser(add_help=True, description='This script will launch a SMB Server and add a share specified as an argument.')
	parser.add_argument('shareName', action='store', help='name of the share to add')
	parser.add_argument('sharePath', action='store', help='path of the share to add')
	parser.add_argument('-port', action='store', default='445', help='TCP port for listening incoming connections (default 445)')
	parser.add_argument('-smb2support', action='store_true', default=False, help='SMB2 Support (experimental!)')
	args = parser.parse_args()

	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit(1)

	logger.init(True)
	logging.getLogger().setLevel(logging.INFO)

	server = smbserver.SimpleSMBServer(listenAddress='0.0.0.0', listenPort=int(args.port))
	server.addShare(args.shareName.upper(), args.sharePath, '')
	server.setSMB2Support(args.smb2support)
	server.setSMBChallenge('')
	server.setLogFile('')

	try:
		server.start()
	except KeyboardInterrupt:
		print('Got CTRL-C, exiting...')
		sys.exit(1)


if __name__ == '__main__':
	main()
