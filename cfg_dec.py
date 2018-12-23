#!/usr/bin/python
################################################################
# surrealiz3
################################################################
#
#  grab you encrypted config file 
#  grab RIP_ID_RANDOM_KEY_B_0x0108-... from eripv2 parser
#  python ../cfg_dec.py --randb RIP_ID_RANDOM_KEY_B_0x0108-... --cfg config.bin 
#  find config.bin.plain decrypted
#
#


from hexdump import hexdump
from Crypto.Cipher import AES
from hashlib import sha1
import hmac
import argparse

parser = argparse.ArgumentParser()

parser.add_argument('--randb' , help='',required=True)
parser.add_argument('--cfg' , help='',required=True)
args = parser.parse_args()
tmp = vars(args)

fnrandb = tmp['randb']
fncfg   = tmp['cfg']

fcfg = open(fncfg,'rb')


print("-------------------------------- HDR ---------------------")
l = fcfg.readline()
hexdump(l)
while l:
    l = fcfg.readline()
    hexdump(l)
    if l == b"\n":
        stcry = fcfg.tell()
        break
print("")

fcfg.seek(0)

cfg = fcfg.read()
fcfg.close()

frandb = open(fnrandb, 'rb')
randb = frandb.read()
frandb.close()

randb_key = randb[0:32]
print("-------------------------------- AESk --------------------")
hexdump(randb_key)
print("")

randb_sigk = randb[0:64]

print("-------------------------------- SIGk --------------------")
hexdump(randb_sigk)
print("")

cfg_crypt_blk = cfg[stcry:-20]
IV = cfg_crypt_blk[0:16]

cfg_digest_blk = cfg[-20:]
print("-------------------------------- DIGST -------------------")
hexdump(cfg_digest_blk)
print("")

aes = AES.new(randb_key, AES.MODE_CBC, IV)
dec = aes.decrypt(cfg_crypt_blk[16:])

hash = hmac.new(randb_sigk,cfg[:-20],sha1)
digst = hash.digest()

print("-------------------------------- CDIGST ------------------")
hexdump(digst)
print("")

if cfg_digest_blk != digst:
    print(" [*] !!! HMAC-SHA1 failed ,something is wrong or no sig check is required !!! check plain contents")

print("\n [*] dumping to file: %s" % fncfg + ".plain\n") 
f = open(fncfg+'.plain','wb')
f.write(cfg[:stcry])
f.write(dec)
f.close



