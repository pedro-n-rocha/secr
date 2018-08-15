#!/usr/bin/python2
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

args = parser.parse_args()
tmp = vars(args)
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

eck = unhexlify(tmp['eckey'])
eik = None
fsh = ''

# o.O #
RIPS = { 
        0x0000:  'RIP_ID_LOWER_CHECKSUM',                  
        0x0002:  'RIP_ID_UNPROT_FREE1',                    
        0x0004:  'RIP_ID_PART_NBR_VARIANT',                
        0x0010:  'RIP_ID_ICS',                             
        0x0012:  'RIP_ID_BOARD_SERIAL_NBR',                
        0x0022:  'RIP_ID_FACTORY_RELEASE_DATE',            
        0x0028:  'RIP_ID_FIA',                             
        0x002C:  'RIP_ID_HANDOVER_DATE',                   
        0x0032:  'RIP_ID_LAN_ADDR',                        
        0x0038:  'RIP_ID_COMPANY_ID',                      
        0x003C:  'RIP_ID_FACTORY_ID',                      
        0x0040:  'RIP_ID_BOARD_NAME',                      
        0x0048:  'RIP_ID_MEMORY_CONFIG',                   
        0x004C:  'RIP_ID_USB_LAN_ADDR',                    
        0x0083:  'RIP_ID_MODEM_ACCESS_CODE',               
        0x0088:  'RIP_ID_SECURE_REMOTE_MANG_PASWD',        
        0x008D:  'RIP_ID_WLAN_LAN_ADDR',                   
        0x0100:  'RIP_ID_PUBLIC_DSA_SYST',                 
        0x0101:  'RIP_ID_PUBLIC_DSA_RESC',                 
        0x0102:  'RIP_ID_MODELNAME',                       
        0x0103:  'RIP_ID_PRODUCT_CLASS',                   
        0x0104:  'RIP_ID_LB_CLIENT_CERTIFICATE',           
        0x0105:  'RIP_ID_PRIVATE_KEY',                     
        0x0106:  'RIP_ID_H235_KEY',                        
        0x0107:  'RIP_ID_RANDOM_KEY_A',                    
        0x0108:  'RIP_ID_RANDOM_KEY_B',                    
        0x0109:  'RIP_ID_KEY_PWD',                         
        0x0112:  'RIP_ID_RALINK_CALIBRATION_DATA',         
        0x0115:  'RIP_ID_CHIPID',                          
        0x0116:  'RIP_ID_PUBLIC_RSA_KEY',                   
        0x0118:  'RIP_ID_SERIAL_NBR_BYTES',                
        0x011A:  'RIP_ID_CLIENT_CERTIFICATE',              
        0x011B:  'RIP_ID_OPTICAL_FRONT_END',               
        0x011C:  'RIP_ID_DUID_LLT',                        
        0x011E:  'RIP_ID_EIK',                            
        0x011F:  'RIP_ID_ECK',                            
        0x0120:  'RIP_ID_OSIK',                            
        0x0121:  'RIP_ID_OSCK',                            
        0x0122:  'RIP_ID_RESTRICTED_DOWNGR_TS',            
        0x0123:  'RIP_ID_RESTRICTED_DOWNGR_OPT',           
        0x0124:  'RIP_ID_GENERIC_ACCESS_KEY_LIST',         
        0x0125:  'RIP_ID_UNLOCK_TAG',                      
        0x0127:  'RIP_ID_OLYMPUS_IK',                      
        0x0128:  'RIP_ID_OLYMPUS_CK',                      
        0x4001:  'RIP_ID_ID_DECT_CFG'                      

}
xRIPS=dict(zip(RIPS.values(),RIPS.keys()))

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
   dec = aes.decrypt(str(encdata))
   pad = struct.unpack('>B',dec[len(dec)-1])[0]
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

def get_idx(IDx):
    x=1 
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
    e = long('10001', 16)
    n = long(hexlify(pub_mod),16)
    eik = construct((n, e))

def dump(id,data):
    fn = "%s_0x%.4x-%s "%(RIPS[id],id,fsh[0:8])if id in RIPS else"RIP_UNK_0x%.4x-%s"%(id,fsh[0:8]) # .. :P 
    print "dumping to file  %s ...." % fn.strip() 
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
        item = get_idx(ID) # double walking for god sake fixit .... 
        if(~item.attr_hi &  ATTR_CRYPTO):
            if(~item.attr_hi &  ATTR_ECK_ENCR):
                dec = decrypt_aes_sigret(item.data,eck)
                if(~item.attr_hi &  ATTR_EIK_SIGN):
                    print "%s EIK_SIGNED and ECK_ENCR" % parse_rip(ID)
                    if signverify(item.id,dec.data,dec.signature):
                        print 'SIG: OK'
                        dump(item.id,dec.data)
                    else:
                        print 'SIG: NOK , ECK wrong ???!! not dumping contents!!'
                else:
                    print "%s ECK_ENCR only" % parse_rip(ID)
                    dump(item.id,dec.data)
            else:
                if(~item.attr_hi &  ATTR_EIK_SIGN):
                    print "%s EIK_SIGNED only" % parse_rip(ID) 
                    dec = sigret(item.data);
                    if signverify(item.id,dec.data,dec.signature):
                        print 'SIG: OK'
                        dump(item.id,dec.data)
                    else:
                        print 'SIG: NOK , ECK wrong ???!! not dumping contents!!'

            if(~item.attr_hi &  ATTR_BEK_ENCR):
                if(item.attr_hi &  ATTR_MCV_SIGN):
                    print "%s MCV_SIGNED and BEK_ENCR !UNSUPPORTED!!" % parse_rip(ID)
                    item.data = data[0:len(data)-256] # remove sig rsa 256 
                else:
                    print "%s BEK_ENCR only !!UNSUPPORTED!!"  % parse_rip(ID) #no bek yet :/ 
            else: 
                if(~item.attr_hi &  ATTR_MCV_SIGN):
                    print "%s MCV_SIGNED only" % parse_rip(ID) 
                    dec = sigret(item.data) 
                    dump(item.id,dec.data) # no integrity check ... 
        else:
            print "%s no_crypt" % parse_rip(ID)
            dump(item.id,item.data)
        print""

def init():
    global fsh
    fsh = sha256_checksum(fname)
    item =  get_idx(xRIPS['RIP_ID_EIK'])
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
