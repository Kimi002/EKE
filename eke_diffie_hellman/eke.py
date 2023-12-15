from dhmath import b64e, power, miller_rabin_test, get_safe_prime
import random
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.number import getPrime
import os

class DiffieHellman:

    salt = b'K\x03\xea\x8dy\x9b\x83\x17\xc7\xd9t5[_\xda+'

    def __init__(self, a: int, g: int, p: int):
        self.a = a
        self.g = g
        self.p = p
        self.key = power(g,a,p)

    def gen(self):
        # generate public key
        return self.key
    
    
    def get_dh_exchange_key(self,r_other):
        # returns secret common exchange key
        self.exchange_key = power(r_other, self.a, self.p)

        return self.exchange_key
    
    def get_AES_key(self):
        # key derivation function used to derive 128 bit AES key
        aes_key = scrypt(str(self.exchange_key).encode(), DiffieHellman.salt, 16, N=2**14, r=8, p=1)
        return aes_key
    
    def set_salt(new_salt):
        DiffieHellman.salt = new_salt

    def encrypt(self, secret_key_bytes, encryption_bytes):
        iv_encrypt = Random.get_random_bytes(16)
        R_encrypt = AES.new(secret_key_bytes, AES.MODE_CBC, iv_encrypt)
        encrypted = b64e(R_encrypt.encrypt(pad(encryption_bytes, AES.block_size)))
        return encrypted, iv_encrypt

    def decrypt(self, secret_key_bytes, iv, decryption_bytes):
        R_decrypt = AES.new(secret_key_bytes, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(R_decrypt.decrypt(decryption_bytes), AES.block_size)

        return decrypted_bytes
    
    @staticmethod
    def get_DH_params():
        p = 329634315527744090434366880013961608374879522465429005392673672125101761178978775144985926658799057874619640941823475369262957823963618464266260983369607580737120061543023854625556202383515406810644630978443162654952065573411451813150059932730020235941430751964199127951884019266277196168486884660177071867967
        g = 17602788688484354871984061181491143039741831003495593059132439527972832817584801107160706870013867738821391635015148358469995695696928895545691281848207100475434709921039085235959236789498954556505672352552809588399148005892261566513301865906097195043891243159028240342554416635390377600356841461025495136657

        return {"modulus": p, "generator": g}

        while True:
            q = getPrime(1024)
            # print(miller_rabin_test(q))
            p = get_safe_prime(q)
            # print(miller_rabin_test(p))
            # print("got p")
            if p == -1:
                continue
            print("modulus =",p)
            print(miller_rabin_test(q))
            while True:
                print("hi", end = ",")
                g = random.randint(10,p-1)
                # legendre = g ** ((p-1)/2) (mod p)
                exp = (p-1)//2
                # print(exp==q, end=",")
                if power(g,exp,p) == p-1:
                    break
            print()
            print(power(g,q,p))
            print()
            print("g=", g)
            break

        with open("./DH_params.txt", "a") as f:
            f.write("p = ")
            f.write(str(p))
            f.write('\n')
            f.write("g = ")
            f.write(str(g))
            f.write('\n')
            f.write("------------------------")
            f.write('\n')
        
        return {"modulus": p, "generator": g}
