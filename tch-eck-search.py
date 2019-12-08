#!/usr/bin/python3
################################################################
# https://github.com/jameskeenan295/tch-eck-search
# Based on eripv2.py script by surrealiz3.
# Updated to automatically find the ECK from a memory dump instead of relying on the user to specify it
# Dumps all the eripv2 objects to disk when it finds the right ECK
# Usually finds ECK within ~10 seconds. Worst case is ~24 hours.  It will try the faster methods first, then fall-back to an exhaustive search through all bytes in the mem dump
# OCK key file is of relevance to decrypt encrypted rbi firmware files with another script 
################################################################
##
## ## From an ssh shell on your router, dump these two things to a USB flash disk:
## 1) Dump your eripv2 partition mtd5 for offline processing: dd if=/dev/mtd5 of=/mnt/usb_path/mtd5.dump  
## 2) Dump your memory for offline processing: dd if=/dev/mem of=/mnt/usb_path/mem.dump bs=1024
##
## copy both dump files to where you are able to run this python3 script 
##
## run: python3 eripv3.py --eripv2 mtd5.dump --memdump mem.dump

import struct, time, argparse, hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey.RSA import construct
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from binascii import hexlify


parser = argparse.ArgumentParser()
parser.add_argument('--eripv2', help='eripv2 dump file name ( grab with: dd if=/dev/mtd5 of=/mnt/usb_path/mtd5.dump)')
parser.add_argument('--debug' , help='enable debugging')
parser.add_argument('--memdump', help='memdump file name ( grab with: dd if=/dev/mem of=/mnt/usb_path/mem.dump bs=1024 )')

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

eik = None
fsh = ''
osck = bytes(1)
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
        0x4001:  'RIP_ID_ID_DECT_CFG',
        0x8001:  'RIP_ID_PRODUCT_ID',
        0x8003:  'RIP_ID_VARIANT_ID'

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
    print("dumping RIP ID %s to file  %s ...." % (id,fn.strip())) 
    f = open(fn.strip(),'wb')
    f.write(data)
    f.close()
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
        if DEBUG: print("%.4x" % item.addr)
        if(~item.attr_hi &  ATTR_CRYPTO):
            if(~item.attr_hi &  ATTR_ECK_ENCR):
                dec = decrypt_aes_sigret(item.data,eck)
                if(~item.attr_hi &  ATTR_EIK_SIGN):
                    if DEBUG: print("%s EIK_SIGNED and ECK_ENCR" % parse_rip(ID))
                    if signverify(item.id,dec.data,dec.signature):
                        if DEBUG: print('SIG: OK (proves provided ECK is correct)')
                        dump(item.id,dec.data,x-1)
                    else:
                        print('SIG: NOK (ECK wrong ???!! not dumping contents!!)')
                        if DEBUG:
                            dump(item.id,dec.data,x-1)
                else:
                    if DEBUG: print("%s ECK_ENCR only" % parse_rip(ID))
                    dump(item.id,dec.data,x-1)
            else:
                if(~item.attr_hi &  ATTR_EIK_SIGN):
                    if DEBUG: print("%s EIK_SIGNED only" % parse_rip(ID)) 
                    dec = sigret(item.data);
                    if signverify(item.id,dec.data,dec.signature):
                        if DEBUG: print('SIG: OK (proves parsed EIK is correct)')
                        dump(item.id,dec.data,x-1)
                    else:
                        print('SIG: NOK (EIK wrong ???!! not dumping contents!!)')
                        if DEBUG:
                            dump(item.id,dec.data,x-1)

            if(~item.attr_hi &  ATTR_BEK_ENCR):
                if(item.attr_hi &  ATTR_MCV_SIGN):
                    if DEBUG: print("%s MCV_SIGNED and BEK_ENCR !UNSUPPORTED!!" % parse_rip(ID))
                    item.data = data[0:len(data)-256] # remove sig rsa 256 
                else:
                    if DEBUG: print("%s BEK_ENCR only !!UNSUPPORTED!!"  % parse_rip(ID)) #no bek yet :/ 
            else: 
                if(~item.attr_hi &  ATTR_MCV_SIGN):
                    if DEBUG: print("%s MCV_SIGNED only" % parse_rip(ID)) 
                    dec = sigret(item.data) 
                    dump(item.id,dec.data,x-1) # no integrity check ... 
        else:
            if DEBUG: print("%s no_crypt" % parse_rip(ID))
            dump(item.id,item.data,x-1)

def eripv2_test_eck_osck(item):
    global osck
    if(~item.attr_hi &  ATTR_CRYPTO):
        if(~item.attr_hi &  ATTR_ECK_ENCR):
            dec = decrypt_aes_sigret(item.data,eck)
            if(~item.attr_hi &  ATTR_EIK_SIGN):
                if signverify(item.id,dec.data,dec.signature):
                    #Success ECK is correct
                    osck = dec.data
                    return True
    return False    

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

def eck_found():
    eripv2_walk()
    print("ECK found: ", str((hexlify(eck)),"utf-8"), " : writing to files:  ECK and ECK.hex")
    f = open('ECK','wb')
    f.write(eck)
    f.close()
    f = open('ECK.hex','w')
    f.write(str((hexlify(eck)),"utf-8"))
    f.close()
    if(osck != 0) : print("OSCK found: ", str((hexlify(osck)),"utf-8"))
    return True

def ecksearch():
    global eck
    patterns_to_ignore = []
    patterns_to_ignore.append(bytes(16)) # ignore keys that are all 00
    patterns_to_ignore.append(b'\F' * 16) # ignore keys that are all FF
    
    ## Read the memdump file, then close it
    memdump_fname = tmp['memdump'] 
    memdump_f = open(memdump_fname , 'rb')
    memdump_data = memdump_f.read()
    memdump_f.close()
    memdump_len=len(memdump_data)
    
    osck_item = get_idx(0x0121,1) # gets the encrypted OSCK structure from eripv2 dump, which will be used many times as we test each potential key and check the signatures

    #----Start of search for likely offsets where ECK might be nearby ----------
    search_before = 2048 # number of bytes to search before a candidate
    search_after = 4096 # number of bytes to search ahead of a candidate
    candidates = []
    position = 0
    curpos = 0
    print("Searching for likely candidate offsets...")
    while (curpos < memdump_len):
        position = memdump_data[curpos:].find(b'\x72\x69\x70\x64\x72\x76\x00\x00\x00') # most likely candidates have a few \x00 bytes after
        if (position > 0):
            curpos = curpos + position + 1
            if(curpos-1 not in candidates) : candidates.append(curpos-1)
            continue
        else: break
    position = 0
    curpos = 0
    
    while (curpos < memdump_len):
        position = memdump_data[curpos:].find(b'\x72\x69\x70\x64\x72\x76') # less likely candidates
        if (position > 0):
            curpos = curpos + position + 1
            if(curpos-1 not in candidates) : candidates.append(curpos-1)
            continue
        else: break
    print("Found ", len(candidates), " possible candidate offsets to try")
    #-----End of search for offsets-------
    
    #-----Start of search from likely candidate offsets -----------
    print("Starting search using likely candidate offsets...")
    for candidate in candidates:
        memdump_pos = candidate + search_after # start search from end and work backwards.
        
        while (memdump_pos >= (candidate - search_before)) :
            eck = memdump_data[memdump_pos:memdump_pos+16]
            memdump_pos -= 1
            if (eck in patterns_to_ignore): continue # ignore ECK's that are all zeros or ones (performance optimization)
            if(eripv2_test_eck_osck(osck_item)): return eck_found()
       
    # ---- Start of exhaustive search of all bytes in mem dump ----------------
    print("Starting exhaustive search of all bytes in memdump, this may take a long time (roughly 24hrs)")
    memdump_pos = memdump_len - 16 # start search from end of memdump and work backwards. evidence suggests the ECK is never near the start, always towards the end
    while (memdump_pos >=0) :
        eck = memdump_data[memdump_pos:memdump_pos+16]
        memdump_pos -= 1
        if memdump_pos % 12800 == 0:
            progress = ((memdump_len - memdump_pos) / memdump_len) * 100
            elapsedtime = time.time() - starttime
            secondsremaining = (elapsedtime / progress) * (100 - progress)
            m, s = divmod(secondsremaining, 60)
            h, m = divmod(m, 60)
            print("{:.2f}".format(progress), '% complete. ', "Estimated time remaining = %d:%02d:%02d" % (h, m, s))
        
        if (eck in patterns_to_ignore): continue # ignore ECK's that are all zeros or ones (performance optimization)
        if(eripv2_test_eck_osck(osck_item)): return eck_found()
            
    print("ECK was not found")

starttime = time.time()    # used for measuring elapsed time
init()
print("Init completed, starting search process")
ecksearch()
endtime = time.time()    # used for measuring elapsed time
print("Done! ", "{:.1f}".format(endtime - starttime), 'sec elapsed time')
