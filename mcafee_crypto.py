#!/usr/bin/env python3
"""Module to provide various McAfee Crypto Functions"""
import struct
import zlib

from Crypto.Cipher import DES3
from Crypto.Hash import SHA
from Crypto.PublicKey import DSA
from Crypto.Random import random
from Crypto.Signature import PKCS1_v1_5


def SHA1(message):
    digest = SHA.new()
    digest.update(message)
    return digest.digest()


def data_compress(data):
    return zlib.compress(data)


def generate_DSA_agentkey():
    key = DSA.generate(1024)
    agent_pubkey_epo_format = b'\x01\x00\x0c\x00' \
    + b'agpubkey.bin' \
    + b'\x9c\x01\x00\x00' \
    + b'\x40\x00' + key.p.to_bytes(128, 'little') \
    + b'\x00\xa0' + key.q.to_bytes(20, 'little') \
    + b'\x03\xff' + key.g.to_bytes(128, 'little') \
    + b'\x03\xfc' + key.y.to_bytes(128, 'little')
    return agent_pubkey_epo_format


def decode_DSA_agentkey(coded_key):
    preamble = coded_key[0:4]
    print(preamble)
    keystring = coded_key[4:16]
    print(keystring)
    key_len = coded_key[16:20]
    print(key_len)
    key_p = coded_key[20:150]
    print(key_p)
    key_q = coded_key[150:172]
    print(key_q)
    key_g = coded_key[172:302]
    print(key_g)
    key_y = coded_key[302:432]
    print(key_y)


def decrypt_3des(message):
    key = bytes.fromhex('3ef136b8b33befbc3426a7b54ec41a377cd3199b')
    # key = SHA1(b'\<!@#$%^>')
    key += b'\x00\x00\x00\x00'
    des3 = DES3.new(key, DES3.MODE_ECB)
    decrypted = des3.decrypt(message)
    return decrypted


def encrypt_3des(message):
    key = bytes.fromhex('3ef136b8b33befbc3426a7b54ec41a377cd3199b')
    key += b'\x00\x00\x00\x00'
    des3 = DES3.new(key, DES3.MODE_ECB)
    encrypted = des3.encrypt(message)
    return encrypted


def rsa_sign(signkey, message):
    signer = PKCS1_v1_5.new(signkey)
    digest = SHA.new()
    digest.update(message)
    sign = signer.sign(digest)
    return sign


def dsa_sign(dsakey, message):
    dsakey = DSA.construct(dsakey)
    h = SHA.new(message).digest()
    k = random.StrongRandom().randint(1, dsakey.q-1)
    sign = dsakey.sign(h,k)
    sign_r = sign[0].to_bytes(20, 'big')
    sign_s = sign[1].to_bytes(20, 'big')
    signature = struct.pack('<B', 4 + len(sign_r) + len(sign_s)) + b'\x00\x00\x00' + b'\x00' + \
                struct.pack('<B', len(sign_r)*8) + sign_r + b'\x00' + struct.pack('<B', len(sign_s)*8) + sign_s
    return signature


def dsa_sign_validate(key, signature, message):
    dsakey = DSA.construct(key)
    h = SHA.new(message).digest()
    if dsakey.verify(h,signature):
        return True
    else:
        return False


def xo8_decode(data, key):
    output = b''
    xor_byte = 0
    xor_initkey = key
    xor_key = xor_initkey
    for index in range(len(data)):
        if (index % 8) == 0:
            xor_key = xor_initkey
        else:
            xor_key = xor_byte
        xor_byte = data[index]
        output += bytes([(xor_byte^xor_key)])
    return output


def xo8_encode(data, key):
    output = b''
    xor_byte = 0
    xor_initkey = key
    xor_key = xor_initkey
    for index in range(len(data)):
        xor_byte = data[index]
        xor_byte = xor_byte ^ xor_key
        output += bytes([xor_byte])
        if (index + 1) % 8 == 0:
            xor_key = xor_initkey
        else:
            xor_key = xor_byte
    return output


def mcafee_3des_encrypt(message):
    #  McAfee 3DES = XOR8 + 3DES + tags
    padding_len = len(message) % 8
    message += b'\x00' * padding_len * 7
    message = xo8_encode(message, 0x54)
    encrypted_message = encrypt_3des(message)
    mcafee_data_encrypted = b'\x45\x50\x4f\x00' + b'\x02\x00\x00\x00' \
                            + struct.pack('<I', len(encrypted_message)) + encrypted_message
    return mcafee_data_encrypted


def mcafee_3des_decrypt(encrypted_message):
    encrypted_message = encrypted_message[12:]
    message = decrypt_3des(encrypted_message)
    return xo8_decode(message, 0x54)


def xor_c(a):
    return bytes(bytearray([b ^ 0xaa for b in bytearray(a)]))


def mcafee_compress(message):
    compress_message = zlib.compress(message)
    return struct.pack('<I', len(message)) + struct.pack('<I', len(compress_message)) + compress_message




