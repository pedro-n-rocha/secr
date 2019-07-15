#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Decrypt script by Kbios
#Modified by Ansuel

print("DecryptScript creato da Ansuel && Kbios and enhanced by some random strangers :)")

import sys, struct, zlib, binascii, hexdump, argparse

try:
	from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
	from cryptography.hazmat.backends import default_backend

except ImportError or ModuleNotFoundError:
		print("The Cryptography module is missing")
		install=input("Install? (Y/n): ")
		if install == "" or install == "Y" or install == "y":
			import pip
			
			pip.main(["install", "cryptography" ])
			
			from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
			from cryptography.hazmat.backends import default_backend
		else:
			print("This script can't run without the modules installed.")
			input()
			sys.exit(1)

def dumptofile( file , newext, data ):
	output_name = file[:(file.find(".rbi"))]+newext
	output_file = open(output_name,"w+b")
	output_file.write(data)
	output_file.close()

def decrypt( file , key, debug=False ):
	datafile = open( file, "rb")
	globalheader = datafile.read(0x134)
	if debug:
		print('globalheader: ')
		hexdump.hexdump(globalheader)
	payloadstart = struct.unpack_from(">H", globalheader, 0x2A)[0]
	datafile.seek(payloadstart)
	data = datafile.read()
	
	while True:
		payloadtype = data[0]
		print("Layer type %X being handled" % payloadtype)
		if payloadtype == 0xB0: # cleartext
			if debug:
				dumptofile(file, "_B0cleartext.bin", data)
			data = data[1+4+1:]
			break
		elif payloadtype == 0xB8: # sha256
			if debug:
				dumptofile(file, "_B8sha265.bin", data)
			data = data[1+4+1+4+32:]
		elif payloadtype == 0xB4: # zip
			if debug:
				dumptofile(file, "_B4zip.bin", data)
			data = zlib.decompress(data[1+4+1+4:])
		elif payloadtype == 0xB7: # aes256
			if debug:
				dumptofile(file, "_B7aes256.bin", data)
			if key is None:
				print("osck not provided - fail", file=sys.stderr)
				sys.exit(1)
			data = data[1+4+1+4:] # "\xB7" % "MUTE" % "\n" % payloadSize
			iv = data[:16]
			if debug:
				print('iv1: ')
				hexdump.hexdump(iv)
			keydata = data[16:64]
			if debug:
				print('keydata1: ')
				hexdump.hexdump(keydata)
			backend = default_backend()
			cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
			decryptor = cipher.decryptor()
			keydata = decryptor.update(keydata) + decryptor.finalize()
			if debug:
				print('keydata2: ')
				hexdump.hexdump(keydata)
			key = keydata[:-keydata[-1]]
			if debug:
				print('key2: ')
				hexdump.hexdump(key)
			iv = data[64:80]
			if debug:
				print('iv2: ')
				hexdump.hexdump(iv)
			cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
			decryptor = cipher.decryptor()
			data = decryptor.update(data[80:]) + decryptor.finalize()
			data = data[:-data[-1]]
		else:
			raise Exception("There is no handler for this payload type.  Is the decyption key correct?")
	
	dumptofile(file, ".bin", data)
	
	print("Decrypted file saved as .bin")
	print("Use binwalk on this file to extract")
	

def _main():
	try:
		parser = argparse.ArgumentParser()
		parser.add_argument('--rbi', help='.rbi firmware file name')
		parser.add_argument('--osckey', help='key file for your board')
		parser.add_argument('--debug', help='dump every BLI layer into separate file')
		args = parser.parse_args()
		file=vars(args)['rbi'].replace('"', '').strip()
		debug=False if vars(args)['debug'] == None else True
		
		if file != "" and file.endswith("rbi"):
			keyfile=vars(args)['osckey'].replace('"', '').strip()
			if keyfile != "" and ( keyfile.endswith(".osck") or keyfile.endswith(".osckhex") ):
				if keyfile.endswith(".osck"):
					f = open(keyfile, 'r+b')
					keydata = f.read()
					f.close()
				elif keyfile.endswith(".osckhex"):
					f = open(keyfile, 'r+b')
					keydata = binascii.unhexlify(f.read())
					f.close()
			else:
				raise Exception("Sorry but '" + keyfile + "' is an invalid filename")
			
			return decrypt(file , keydata, debug)
		else:
			print("Invalid file name")
	except KeyboardInterrupt:
		print("Program Terminated")

_main()
		
