from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad,unpad
import time
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256, SHA512, SHA3_256


def aes_cbc(key_size, data):
    aescbcst_16key = time.time_ns()
    key = get_random_bytes(key_size)
    aescbcet_16key = time.time_ns()
    ciphercbc = AES.new(key, AES.MODE_CBC)
    aescbcst_16enc = time.time_ns()
    enc_data = ciphercbc.encrypt(pad(data, AES.block_size))
    aescbcet_16enc = time.time_ns()
    ciphercbc2 = AES.new(key, AES.MODE_CBC, ciphercbc.iv)
    aescbcst_16dec = time.time_ns()
    dec_data = unpad(ciphercbc2.decrypt(enc_data), AES.block_size)
    aescbcet_16dec = time.time_ns()
    aescbctt_16key = aescbcet_16key - aescbcst_16key
    aescbctt_16enc = aescbcet_16enc - aescbcst_16enc
    aescbctt_16dec = aescbcet_16dec - aescbcst_16dec
    if data ==  dec_data:
        print('AES CBC cipher works for file size '+str(len(data)))
    else:
        print('AES CBC cipher does not work for file size '+str(len(data)))
    print('time for AES CBC key generation: '+ str(aescbctt_16key))
    print('time for AES CBC encryption for file size '+str(len(data))+ ': '+ str(aescbctt_16enc) + ' total, ' +str(aescbctt_16enc/len(data)) +' per byte')
    print('time for AES CBC decryption for file size '+str(len(data))+': ' + str(aescbctt_16dec) + ' total, ' +str(aescbctt_16dec/len(data)) +' per byte')

def aes_ctr(key_size, data):
    aesctrst_key = time.time_ns()
    key = get_random_bytes(key_size)
    aesctret_key = time.time_ns()
    cipherctr = AES.new(key, AES.MODE_CTR)
    aesctrst_enc = time.time_ns()
    enc_data = cipherctr.encrypt(data)
    aesctret_enc = time.time_ns()
    cipherctr2 = AES.new(key, AES.MODE_CTR, nonce=cipherctr.nonce)
    aesctrst_dec = time.time_ns()
    dec_data = cipherctr2.decrypt(enc_data)
    aesctret_dec = time.time_ns()
    aesctrtt_key = aesctret_key - aesctrst_key
    aesctrtt_enc = aesctret_enc - aesctrst_enc
    aesctrtt_dec = aesctret_dec - aesctrst_dec
    if data ==  dec_data:
        print('AES CTR cipher works for key size ' + str(key_size*8) +' and file size '+str(len(data)))
    else:
        print('AES CTR cipher does not work for key size ' + str(key_size*8) +' and file size '+str(len(data)))
    print('time for AES CTR key generation for key size ' + str(key_size*8) +': ' + str(aesctrtt_key))
    print('time for AES CTR encryption for key size ' + str(key_size*8) +' and file size '+str(len(data))+': ' + str(aesctrtt_enc) + ' total, ' +str(aesctrtt_enc/len(data)) +' per byte')
    print('time for AES CTR decryption for key size ' + str(key_size*8) +' and file size '+str(len(data))+': ' + str(aesctrtt_dec) + ' total, ' +str(aesctrtt_dec/len(data)) +' per byte')

def rsa_cipher(key_size, data):
    rsast_key = time.time_ns()
    key = RSA.generate(key_size)
    rsaet_key = time.time_ns()
    if key_size == 2048:
        block = 214
    elif key_size ==  3072:
        block = 342
    else:
        print("Incorrect key size")
        return
    pub = key.publickey().export_key()
    priv = key.export_key()
    pubkey = RSA.importKey(pub)
    cipher1 = PKCS1_OAEP.new(pubkey)
    i=0
    enc_data=b''
    rsast_enc = time.time_ns()
    while i<=len(data)//block:
        ciphertext = cipher1.encrypt(data[i*block:(i+1)*block])
        enc_data = enc_data + ciphertext
        i=i+1
    rsaet_enc = time.time_ns()
    dec_data = b''
    j = 0
    privkey = RSA.importKey(priv)
    cipher2 = PKCS1_OAEP.new(privkey)
    rsast_dec = time.time_ns()
    while j<len(enc_data)/(block+42):
        dec_data = dec_data+cipher2.decrypt(enc_data[j*(block+42):(j+1)*(block+42)])
        j=j+1
    rsaet_dec = time.time_ns()    
    if data == dec_data:
        print('RSA cipher works for key size ' + str(key_size)  +' and file size '+str(len(data)))
    else:
        print('RSA cipher does not work for key size ' + str(key_size)  +' and file size '+str(len(data)))
    rsatt_enc = rsaet_enc - rsast_enc
    rsatt_dec = rsaet_dec - rsast_dec
    rsatt_key = rsaet_key - rsast_key
    print('time for RSA key generation for key size ' + str(key_size)  +': ' + str(rsatt_key))
    print('time for RSA encryption for key size ' + str(key_size)  +' and file size '+str(len(data))+': ' + str(rsatt_enc) + ' total, ' +str(rsatt_enc/len(data)) +' per byte')
    print('time for RSA decryption for key size ' + str(key_size)  +' and file size '+str(len(data))+': ' + str(rsatt_dec) + ' total, ' +str(rsatt_dec/len(data)) +' per byte')

def dsa_sign(key_size, data):
    dsast_key = time.time_ns()
    key = DSA.generate(key_size)
    dsaet_key = time.time_ns()
    pubkey = key.publickey().export_key()
    hash_obj = SHA256.new(data)
    signer = DSS.new(key, 'fips-186-3')
    dsast_sign = time.time_ns()
    signature = signer.sign(hash_obj)
    dsaet_sign = time.time_ns()
    hash_obj = SHA256.new(data)
    pub_key = DSA.import_key(pubkey)
    dsast_ver = time.time_ns()
    verifier = DSS.new(pub_key, 'fips-186-3')
    try:
        verifier.verify(hash_obj, signature)
        dsaet_ver = time.time_ns()
        print('The message is authentic for key size ' + str(key_size)  +' and file size '+str(len(data)))
    except ValueError:
        print('The message is not authentic for key size ' + str(key_size)  +' and file size '+str(len(data)))
    dsatt_sign = dsaet_sign - dsast_sign
    dsatt_ver = dsaet_ver - dsast_ver
    dsatt_key = dsaet_key - dsast_key
    print('time for DSA key generation for key size ' + str(key_size)  +': ' + str(dsatt_key))
    print('time for DSA signature for key size ' + str(key_size)  +' and file size '+str(len(data))+': ' + str(dsatt_sign) + ' total, ' +str(dsatt_sign/len(data)) +' per byte')
    print('time for DSA verification for key size ' + str(key_size)  +' and file size '+str(len(data))+': ' + str(dsatt_ver) + ' total, ' +str(dsatt_ver/len(data)) +' per byte')

def hashing(data):
    sha256st = time.time_ns()
    sha256 = SHA256.new(data)
    sha256et = time.time_ns()
    sha512st = time.time_ns()
    sha512 = SHA512.new(data)
    sha512et = time.time_ns()
    sha3256st = time.time_ns()
    sha3256 = SHA3_256.new(data)
    sha3256et = time.time_ns()
    sha256tt = sha256et - sha256st
    sha512tt = sha512et - sha512st
    sha3256tt = sha3256et - sha3256st
    print('Time for SHA256 for file size '+str(len(data))+': '+str(sha256tt) + ' total, ' +str(sha256tt/len(data)) +' per byte')
    print('Time for SHA512 for file size '+str(len(data))+': '+str(sha512tt) + ' total, ' +str(sha512tt/len(data)) +' per byte')
    print('Time for SHA3_256 for file size '+str(len(data))+': '+str(sha3256tt) + ' total, ' +str(sha3256tt/len(data)) +' per byte')


if __name__ == "__main__":
    f = open("1kb.txt", "r")
    data_1kb = f.read().encode()
    f = open("1mb.txt", "r")
    data_1mb = f.read().encode()
    f = open("10mb.txt", "r")
    data_10mb = f.read().encode()
    aes_cbc(16, data_1kb)
    aes_cbc(16, data_10mb)
    aes_ctr(16, data_1kb)
    aes_ctr(16, data_10mb)
    aes_ctr(32, data_1kb)
    aes_ctr(32, data_10mb)
    rsa_cipher(2048, data_1kb)
    rsa_cipher(2048, data_1mb)
    rsa_cipher(3072, data_1kb)
    rsa_cipher(3072, data_1mb)
    dsa_sign(2048, data_1kb)
    dsa_sign(2048, data_1mb)
    dsa_sign(3072, data_1kb)
    dsa_sign(3072, data_1mb)
    hashing(data_1kb)
    hashing(data_1mb)
    hashing(data_10mb)
