from __future__ import annotations
import hashlib
from Crypto.Cipher import AES
# The recovered client uses the byte ramp IV (00..0f) for both the CS
# handshake stream and one-shot frame encryption.  A zero IV makes the server
# parse the socket but reject the login immediately with 0x10000001.
IV16=bytes(range(16))
class AES128CBCStream:
    def __init__(self,key16):
        # The recovered client creates persistent CBC cipher objects with the
        # protocol IV.  PyCryptodome keeps the chaining state between calls;
        # reimplementing that by replacing ``iv`` with the last block changes
        # the first block and makes CS reject the login frame.
        self.key=bytes(key16)[:16].ljust(16,b'\0')
        self.enc=AES.new(self.key,AES.MODE_CBC,IV16)
        self.dec=AES.new(self.key,AES.MODE_CBC,IV16)
    def encrypt(self,data):
        data=bytes(data)
        n=(-len(data))%16
        return self.enc.encrypt(data+b'\0'*n)
    def decrypt(self,data):
        n=(len(data)//16)*16
        return self.dec.decrypt(bytes(data)[:n])
def aes_cbc_once(key16,data,encrypt=True,iv=None):
    c=AES.new(bytes(key16),AES.MODE_CBC,iv or b'\0'*16)
    if encrypt and len(data)%16: data += b'\0'*(16-len(data)%16)
    return c.encrypt(data) if encrypt else c.decrypt(data[:(len(data)//16)*16])
def seq2_token(uid,ts,app_id): return hashlib.sha1(f"{app_id}HA{uid}HA{ts}".encode()).hexdigest()
def sha1_hex(b): return hashlib.sha1(b).hexdigest()
