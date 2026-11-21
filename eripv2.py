#!/usr/bin/python3
################################################################
# surrealiz3
################################################################
##  
##  grab your ECK key with r2secr.arm.ko ( insmod r2secr.arm.ko && dmesg )
##  or with r2secr.mips.ko ( insmod r2secr.arm.ko && dmesg  ) 
## 
## output 
##
## 34399.350000] r2secr : 1ffdf000 
## [34399.352000] r2secr_struct : dffdf000 
## [34399.356000] r2secr_struct->magic : d104ea5b 
## [34399.361000] r2secr_struct->items : dffdf008 
## [34399.365000] nextFreeItem->id : 11f 
## [34399.369000] nextFreeItem->length : 16 
## [34399.372000] nextFreeItem->data : 1ffdf020 
## [34399.377000] data_ptr : dffdf020 
## [34399.380000] XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX  |  ................ 
##
## grab you eripv2 partition ,mtd5 for offline processing dd if=/dev/mtd5 of=/tmp/mtd5.dd   
## copy it to where you are able to run this python script 
##
## run: python eripv2.py --eripv2 mtd5.dd --eckey XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
##
## find the secrets on screen and dumped unencrypted contents to files 
## OCK key file is of relevance to decrypt encrypted rbi files with another script 
## disclaimer : use at your own risk 


import struct
from hexdump import hexdump
from Crypto.Cipher import AES
from Crypto.PublicKey.RSA import construct
from Crypto.Signature import PKCS1_v1_5, PKCS1_PSS
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from binascii import hexlify,unhexlify
import binascii
import argparse
import hashlib

parser = argparse.ArgumentParser()
parser.add_argument('--eripv2', help='eripv2 dump file name ( grab with dd if=/dev/mtd5 of=/tmp/mtd5.bin)')
parser.add_argument('--eckey' , help='key file grab with kernel module for your arch (insmod r2secrets.arm && dmesg')
parser.add_argument('--debug' , help='enable debugging')

args = parser.parse_args()
tmp = vars(args)
DEBUG=False if tmp['debug'] == None else True
fname = tmp['eripv2'] 
f = open(fname , 'rb')
data = f.read()
f.close()

dlen=len(data)
buff=data[0:dlen-4]

ATTR_EIK_SIGN = 0x10000000 
ATTR_ECK_ENCR = 0x08000000 
ATTR_MCV_SIGN = 0x04000000 
ATTR_BEK_ENCR = 0x02000000 
ATTR_CRYPTO = (ATTR_EIK_SIGN | ATTR_ECK_ENCR | ATTR_MCV_SIGN | ATTR_BEK_ENCR)

eck = unhexlify(tmp['eckey'].replace(' ', '').replace('"', '').strip())
eik = None
fsh = ''

# o.O #
# Naming verified/refined from Technicolor BCMBCA (BCM63138) DGA4130 / TIM Smart
# Modem Plus (boards VBNT-K/S/O, BL 16.11.1013 & 17.19.1062) + BMIPS VDNT-W.
# Evidence: full eripv2 index parse, /proc/rip/* dumps, CFE stage2 decompile.
# Struct confirmed on BCMBCA too: 18-byte index entries walked backward from
# partition end, addr = u32BE ^ 0x20000, trailing 4 bytes of partition = CRC32.
# Crypto bits in attr_hi are ACTIVE-LOW (0 = protection applied):
# 0x3fffffff = plain, 0x2fffffff = EIK_SIGNED, 0x27ffffff = EIK_SIGNED+ECK_ENCR
# (matches the ~attr_hi tests below).
# On BCMBCA the kernel exposes /proc/rip/<id> with already-decrypted values.
RIPS = {
        0x0000:  'RIP_ID_LOWER_CHECKSUM',
        0x0002:  'RIP_ID_UNPROT_FREE1',                     # 2B binary (0x0492 on DGA4130)
        0x0004:  'RIP_ID_PART_NBR_VARIANT',                 # '37687790' (TIM part number)
        0x0008:  'RIP_ID_BOOT_BANK_STATE',                  # BCMBCA CFE stage2: bank | attempts<<8 | fails<<12 (banktable, 3 fails -> ban). Absent in index = defaults.
        0x0009:  'RIP_ID_BOOT_FLAGS',                       # BCMBCA CFE stage2: 0 = normal boot, other = force BOOT-P (TFTP recovery)
        0x0010:  'RIP_ID_ICS',                              # 'E1' (hardware/ICS revision)
        0x0012:  'RIP_ID_BOARD_SERIAL_NBR',                 # serial BODY; full serial = 0x003C + 0x0012 (e.g. 'CP'+'1719TADZT')
        0x0022:  'RIP_ID_FACTORY_RELEASE_DATE',             # YYMMDD ('170521')
        0x0028:  'RIP_ID_FIA',                              # factory integration site ('ZA')
        0x002C:  'RIP_ID_HANDOVER_DATE',
        0x0032:  'RIP_ID_LAN_ADDR',                         # MAC (adjacent to 0x008D WLAN MAC)
        0x0038:  'RIP_ID_COMPANY_ID',                       # 'TMBB' (TIM-branded board) / 'NCP' (VDNT-W)
        0x003C:  'RIP_ID_FACTORY_ID',                       # serial prefix ('CP'), prepended to 0x0012
        0x0040:  'RIP_ID_BOARD_NAME',                       # 'VBNT-K' (= DGA4130), 'VBNT-S', 'VBNT-O', 'VDNT-W'
        0x0048:  'RIP_ID_MEMORY_CONFIG',                    # 1 byte (0x28); 0x49/4a/4b follow it as 1B sub-configs
        0x0049:  'RIP_ID_BOARD_SUBCFG_A',                   # unknown 1B (value 01 on DGA4130; not in upstream naming)
        0x004A:  'RIP_ID_BOARD_SUBCFG_B',                   # unknown 1B (value 02)
        0x004B:  'RIP_ID_BOARD_SUBCFG_C',                   # unknown 1B (value 03)
        0x004C:  'RIP_ID_USB_LAN_ADDR',                     # MAC (00:90:d0:* = Technicolor OUI, default)
        0x0083:  'RIP_ID_MODEM_ACCESS_CODE',                # ECK-encr, EIK-signed (5B payload)
        0x0088:  'RIP_ID_SECURE_REMOTE_MANG_PASWD',         # ECK-encr, EIK-signed ('EC.S3' on DGA4130)
        0x008D:  'RIP_ID_WLAN_LAN_ADDR',
        0x0100:  'RIP_ID_PUBLIC_DSA_SYST',
        0x0101:  'RIP_ID_PUBLIC_DSA_RESC',
        0x0102:  'RIP_ID_MODELNAME',
        0x0103:  'RIP_ID_PRODUCT_CLASS',
        0x0104:  'RIP_ID_LB_CLIENT_CERTIFICATE',
        0x0105:  'RIP_ID_PRIVATE_KEY',
        0x0106:  'RIP_ID_H235_KEY',
        0x0107:  'RIP_ID_RANDOM_KEY_A',                     # 32B, ECK-encr (index len 320 = IV+enc+sig)
        0x0108:  'RIP_ID_RANDOM_KEY_B',                     # 64B, ECK-encr
        0x0109:  'RIP_ID_KEY_PWD',
        0x0112:  'RIP_ID_RALINK_CALIBRATION_DATA',
        0x0115:  'RIP_ID_CHIPID',                           # == /proc/otp/chipid fuse (0x001341F1); CFE derives EFU keyID from OTP rows 0x13/0x14
        0x0116:  'RIP_ID_PUBLIC_RSA_KEY',
        0x0118:  'RIP_ID_SERIAL_NBR_BYTES',
        0x011A:  'RIP_ID_CLIENT_CERTIFICATE',               # PEM cert chain (7KB index entry, ECK-encr)
        0x011B:  'RIP_ID_OPTICAL_FRONT_END',
        0x011C:  'RIP_ID_DUID_LLT',                         # 4B (DHCP DUID-LLT)
        0x0119:  'RIP_ID_FEATURE_MASK',                     # 256B rw via /proc/rip/new on BCMBCA (feature/restriction mask; bc01 03ff ... per-feature bytes)
        0x011E:  'RIP_ID_EIK',                              # RSA-2048 pub modulus, 512B entry (key+EIK self-sign); present in index but NOT exposed under /proc/rip on BCMBCA
        0x011F:  'RIP_ID_ECK',                              # AES key for records, EIK-signed+eck-wrapped (304B entry)
        0x0120:  'RIP_ID_OSIK',                             # raw RSA-2048 modulus (256B) + EIK sig = 512B. VERIFIED: this is the boot key used by BCMBCA CFE stage2 RSAS engine (image signature chain root). Fleet-wide key (md5 of OSIK string ada4cbd2..., identical across devices/BL builds)
        0x0121:  'RIP_ID_OSCK',                             # companion AES key (OSCK) for RBI image decryption
        0x0122:  'RIP_ID_RESTRICTED_DOWNGR_TS',             # downgrade restriction: enforced by BL >= 17.19 only ('Skip Downgrade Restriction' ENG bit2)
        0x0123:  'RIP_ID_RESTRICTED_DOWNGR_OPT',
        0x0124:  'RIP_ID_GENERIC_ACCESS_KEY_LIST',          # plaintext list of access keys (verified: 'R6E9...' ASCII entries)
        0x0125:  'RIP_ID_UNLOCK_TAG',                       # ENG unlocker (EFU). CONFIRMED on BCMBCA: absent on retail; 264B tag (embedded RSA key + 8B BE flags + sig, key signed by 0x0120) written by /usr/sbin/rip-write-efu.sh -> /proc/rip/0125; CFE gate FUN_00f01eb4: bit0=skip image signature, bit1=skip product/variant check (bit2=skip downgrade in 17.x)
        0x0127:  'RIP_ID_OLYMPUS_IK',                       # raw RSA-2048 modulus, EIK-signed. CONFIRMED: second boot key accepted by BCMBCA CFE stage2 alongside 0x0120 on BLI2/BOOT-P recovery path; static across devices and BL builds (Broadcom 'Olympus' = BCM63138)
        0x0128:  'RIP_ID_OLYMPUS_CK',                       # 32B key (ECK-encr + EIK-signed, index len 320)
        0x012A:  'RIP_ID_PRIVATE_BLOB_A',                   # unknown 2048B ECK-encr blob (BCMBCA/TIM extension; likely key material)
        0x012B:  'RIP_ID_PRIVATE_BLOB_B',                   # unknown 2048B ECK-encr blob (sibling of 0x012A)
        0x012C:  'RIP_ID_TLV_NUMERIC_SECRET',               # plaintext TLV (0x10 0x08 hdr) + 129-digit numeric string (PIN-like, TIM vendor?)
        0x012D:  'RIP_ID_TLV_ALNUM_SECRET_A',               # plaintext TLV (0x10 0x0d) + base62 credential
        0x012E:  'RIP_ID_TLV_ALNUM_SECRET_B',               # plaintext TLV (0x10 0x18) + base62 credential
        0x4001:  'RIP_ID_ID_DECT_CFG',
        0x8001:  'RIP_ID_PRODUCT_ID',                       # rw via /proc/rip on BCMBCA ('0' = unlocked); checked by CFE product/variant gate (skipped by ENG bit1)
        0x8003:  'RIP_ID_VARIANT_ID'                        # rw via /proc/rip on BCMBCA ('0'); companion of 0x8001
}
xRIPS=dict(list(zip(list(RIPS.values()),list(RIPS.keys()))))

class Map(dict):
    def __init__(self, **kwargs):
        super(Map, self).__init__(**kwargs)
        self.__dict__ = self


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


def decrypt_aes_sigret(data,key):
   IV  = data[0:16]
   encdata = data[16:]
   aes = AES.new(key, AES.MODE_CBC, IV)
   dec = aes.decrypt(encdata)
   pad = struct.unpack('>B',bytes([dec[len(dec)-1]]))[0]
   sz = (len(dec) - pad ) -256
   return Map( data = dec[0:sz] , signature = dec[sz:sz+256]) 

def sigret(_data):
    #thin ice 4 256 keys only !! beware.. 
    sz = (len(_data)) -256
    return Map( data = _data[0:sz] , signature = _data[sz:sz+256]) 

def parse_rip(key):
    if key in RIPS :
        return RIPS[key]
    return "RIP_ID_UNKN: 0x%04x" % key

def get_idx(IDx,x):
    ID=0x0000
    while (ID != 0xffff):
        item = buff[len(buff)-(18*x):(len(buff)-(18*x)+18)]
        x=x+1
        ID = struct.unpack('>H',item[0:2])[0]
        if(ID == 0xffff):
            break
        if(ID == IDx):
            rip_item = Map(
                    id=IDx,
                    addr =  struct.unpack('>L',item[2:6])[0]^0x20000 , 
                    attr_lo = (struct.unpack('>L',item[6:10])[0]) , 
                    attr_hi = (struct.unpack('>L',item[10:14])[0]) , 
                    length= struct.unpack('>L',item[14:18])[0],
                    )
            rip_item['data'] = buff[rip_item.addr:rip_item.addr + rip_item.length]
            return rip_item
    return None

def load_eik(pub_mod):
    global eik
    e = int('10001', 16)
    n = int(hexlify(pub_mod),16)
    eik = construct((n, e))

def dump(id,data,pos=None):
    fn = "%s_0x%.4x-%s" %(RIPS[id],id,fsh[0:8]) if id in RIPS else "RIP_UNK_0x%.4x-%s" %(id,fsh[0:8]) # .. :P
    if DEBUG & pos != None:
        fn = "%.2x_" % pos + fn
    print("dumping to file  %s ...." % fn.strip()) 
    f = open(fn.strip(),'wb')
    f.write(data)
    f.close()
    hexdump(data)
    return

def eripv2_walk():
    x=1 
    ID=0x0000
    while (ID != 0xffff):
        item = buff[len(buff)-(18*x):(len(buff)-(18*x)+18)]
        x=x+1
        ID = struct.unpack('>H',item[0:2])[0]
        if(ID == 0xffff):
            break
        item = get_idx(ID,x-1) # walk ahead from found tag
        print("%.4x" % item.addr)
        if(~item.attr_hi &  ATTR_CRYPTO):
            if(~item.attr_hi &  ATTR_ECK_ENCR):
                dec = decrypt_aes_sigret(item.data,eck)
                if(~item.attr_hi &  ATTR_EIK_SIGN):
                    print("%s EIK_SIGNED and ECK_ENCR" % parse_rip(ID))
                    if signverify(item.id,dec.data,dec.signature):
                        print('SIG: OK (proves provided ECK is correct)')
                        dump(item.id,dec.data,x-1)
                    else:
                        print('SIG: NOK (ECK wrong ???!! not dumping contents!!)')
                        if DEBUG:
                            dump(item.id,dec.data,x-1)
                else:
                    print("%s ECK_ENCR only" % parse_rip(ID))
                    dump(item.id,dec.data,x-1)
            else:
                if(~item.attr_hi &  ATTR_EIK_SIGN):
                    print("%s EIK_SIGNED only" % parse_rip(ID)) 
                    dec = sigret(item.data);
                    if signverify(item.id,dec.data,dec.signature):
                        print('SIG: OK (proves parsed EIK is correct)')
                        dump(item.id,dec.data,x-1)
                    else:
                        print('SIG: NOK (EIK wrong ???!! not dumping contents!!)')
                        if DEBUG:
                            dump(item.id,dec.data,x-1)

            if(~item.attr_hi &  ATTR_BEK_ENCR):
                if(item.attr_hi &  ATTR_MCV_SIGN):
                    print("%s MCV_SIGNED and BEK_ENCR !UNSUPPORTED!!" % parse_rip(ID))
                    item.data = data[0:len(data)-256] # remove sig rsa 256 
                else:
                    print("%s BEK_ENCR only !!UNSUPPORTED!!"  % parse_rip(ID)) #no bek yet :/ 
            else: 
                if(~item.attr_hi &  ATTR_MCV_SIGN):
                    print("%s MCV_SIGNED only" % parse_rip(ID)) 
                    dec = sigret(item.data) 
                    dump(item.id,dec.data,x-1) # no integrity check ... 
        else:
            print("%s no_crypt" % parse_rip(ID))
            dump(item.id,item.data,x-1)
        print("")

def init():
    global fsh
    fsh = sha256_checksum(fname)
    item =  get_idx(xRIPS['RIP_ID_EIK'],1)
    if(item != None):
        load_eik(item.data[:256])
    return 

def signverify(id , data , signature):
    signeddata = struct.pack('>H',id)
    signeddata += data
    signer = PKCS1_PSS.new(eik)
    digest = SHA256.new()
    digest.update(signeddata)
    try:
        return signer.verify(digest, signature)
    except:
        return False

init()
eripv2_walk()
