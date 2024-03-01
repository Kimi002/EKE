from dhmath import b64e, power, miller_rabin_test, get_safe_prime, mon_mod_exp
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
        # self.key = power(g,a,p)
        r = 1
        while r < p:
            r <<= 1
        self.r = r
        self.key = mon_mod_exp(g,a,p,r)

    def gen(self):
        # generate public key
        return self.key
    
    
    def get_dh_exchange_key(self,r_other):
        # returns secret common exchange key
        # self.exchange_key = power(r_other, self.a, self.p)
        self.exchange_key = mon_mod_exp(r_other, self.a, self.p, self.r)

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
        p = 44412024865351808903112210249715555795211163705200066363396337086965352003044793170135436688839147067743726050000445665848227474819230760541243481368179705203633779156051714911142482904686547219077424398036481553020810570966116635458033451456440757812558361236136301898569025779849005746412927362386402282371160447833263453722290811440603533940544847662032898337863667912432725332293813455717978410506283079306170333535172506610531189073841048157301261941551608829970323932468957371796383794007716890624870488974285991842250281803550925855906630974451903807049376045760073230742539977151131182456700598224011344991523
        g = 24916629845024853624620105103330370566625036495446981197766961905399677092642490175911854122651446239832918053353453046436934241538111793798966537712069819588410398452041421155716269346464250552225210006433331612007617004898416213283225850528314277828620139749370927301388281653656996078963808577611913058021271318558208269853223120051675002866297429337055692527960328942714561313979778569300713980419780444691541672350726929488219206004142478669971467498390718722387560937696231155027291968579942894691797231423841812354303906354060352841028214307687135097828988986417409635606463812505734700691065150715257940711065
        return {"modulus": p, "generator": g}

        while True:
            q = getPrime(2048)
            # print(miller_rabin_test(q))
            p = get_safe_prime(q)
            # print(miller_rabin_test(p))
            # print("got p")
            if p == -1:
                continue
            print("modulus =",p)
            r = 1
            while r<p:
                r <<= 1
            print(miller_rabin_test(q,r))
            while True:
                print("hi", end = ",")
                g = random.randint(10,p-1)
                # legendre = g ** ((p-1)/2) (mod p)
                exp = (p-1)//2
                # print(exp==q, end=",")
                # if power(g,exp,p) == p-1:
                #     break
                if mon_mod_exp(g,exp,p,r) == p-1:
                    break
            print()
            print(mon_mod_exp(g,exp,p,r))
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
