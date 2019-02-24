#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Decrypt script by Kbios
#Modified by Ansuel

print("DecryptScript creato da Ansuel && Kbios and enhanced by a random stranger :)")

import sys, struct, zlib, binascii
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

def decrypt( file , key ):
	datafile = open( file, "rb")
	globalheader = datafile.read(0x134)
	payloadstart = struct.unpack_from(">H", globalheader, 0x2A)[0]
	datafile.seek(payloadstart)
	data = datafile.read()
	
	while True:
		payloadtype = data[0]
		print("Layer type %X being handled" % payloadtype)
		if payloadtype == 0xB0: # cleartext
			data = data[1+4+1:]
			break
		elif payloadtype == 0xB8: # sha256
			data = data[1+4+1+4+32:]
		elif payloadtype == 0xB4: # zip
			data = zlib.decompress(data[1+4+1+4:])
		elif payloadtype == 0xB7: # aes256
			if key is None:
				print("osck not provided - fail", file=sys.stderr)
				sys.exit(1)
			data = data[1+4+1+4:]
			iv = data[:16]
			keydata = data[16:64]
			backend = default_backend()
			cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
			decryptor = cipher.decryptor()
			keydata = decryptor.update(keydata) + decryptor.finalize()
			key = keydata[:-keydata[-1]]
			iv = data[64:80]
			cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
			decryptor = cipher.decryptor()
			data = decryptor.update(data[80:]) + decryptor.finalize()
			data = data[:-data[-1]]
		else:
			raise Exception("There is no handler for this payload type.  Is the decyption key correct?")
	
	output_name = file[:(file.find("rbi"))]+"bin" #rimuove estensione rbi
	output_file = open(output_name,"w+b") #crea il bin
	output_file.write(data) #Scrive i dati
	output_file.close()
	
	print("Decrypted file saved as ",output_name)
	print("Use binwalk on the file now")
	

def _main():
	try:
		file=input("Please input the name of the firmware: ")
		file=file.replace('"', '').strip()
		
		if file != "" and file.endswith("rbi"):
			keyfile=input("Please input the name of the decryption key: ").replace('"', '').strip()
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
			
			return decrypt(file , keydata)
		else:
			print("Invalid file name")
			return _main()
	except KeyboardInterrupt:
		print("Program Terminated")
	_main()

_main()
		


