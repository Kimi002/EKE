from primes import gen_prime, b64e
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Protocol.KDF import scrypt

class DiffieHellman:
    
    def __init__(self, a: int, g: int, p: int):
        self.a = a
        self.g = g
        self.p = p
        self.key = (g ** a) % p

    def gen(self):
        # generate public key
        return self.key
    
    
    def decode_public_key(self,r_other):
        # returns secret common exchange key
        self.exchange_key = (r_other ** self.a) % self.p
        # TODO - change the way salt is generated
        salt=10
        # key derivation function used to derive 128 bit AES key
        aes_key = scrypt(str(self.exchange_key).encode(), salt, 16, N=2**14, r=8, p=1)
        return aes_key

    def encrypt(self, secret_key_bytes, encryption_bytes):
        iv_encrypt = Random.get_random_bytes(16)
        R_encrypt = AES.new(secret_key_bytes, AES.MODE_CBC, iv_encrypt)
        encrypted = b64e(R_encrypt.encrypt(pad(encryption_bytes, AES.block_size)))
        return encrypted, iv_encrypt

    def decrypt(self, secret_key_bytes, iv, decryption_bytes):
        R_decrypt = AES.new(secret_key_bytes, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(R_decrypt.decrypt(decryption_bytes), AES.block_size)

        return decrypted_bytes
