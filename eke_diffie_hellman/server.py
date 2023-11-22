#!/usr/bin/env python

import socketserver
import os
from eke import *
from json_mixins import JsonServerMixin
from primes import gen_prime, b64e
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
from base64 import b64decode as b64d


class EKEHandler(socketserver.BaseRequestHandler, JsonServerMixin):
    database = {}

    def handle(self):
        self.recv_json()

        try:
            action = self.data["action"]
            if action == "register":
                self.handle_eke_register()
            elif action == "negotiate":
                self.handle_eke_negotiate_key()
                self.receive_message()
            else:
                self.send_json(error=f"Unrecognised action: {action}")
        except KeyError:
            if "success" not in self.data:
                raise

            success = self.data["success"]
            if "message" in self.data:
                message = self.data["message"]
                print(f"Caught exception: {success = } - {message}")
            else:
                print(f"Caught exception: success={success}")

    def handle_eke_register(self):
        user = self.data["username"]
        passwd = self.data["password"]

        if user in self.database:
            self.send_json(success=False, message=f"User already registered")
            return

        self.database[user] = passwd

        self.send_json(success=True, message=f"Successfully registered user {user}")

    def handle_eke_negotiate_key(self):

        # get client's public key, p and g
        encypted_client_key = b64d(self.data["enc_pub_key"])
        iv_decrypt = b64d(self.data["iv"])
        p = (self.data["modulus"])
        g = (self.data["base"])
        pwd = self.database[self.data["username"]]

        # P = AES.new(self.database[self.data["username"]].ljust(16).encode(), AES.MODE_ECB)
        print("p,g,pwd,iv", p,g,pwd,iv_decrypt)

        P_decrypt = AES.new(pwd.ljust(16).encode(), AES.MODE_CBC, iv_decrypt)
        client_key = b2l(unpad(P_decrypt.decrypt(encypted_client_key), AES.block_size))

        a2 = gen_prime(1000,3000) # secret key
        user2 = DiffieHellman(a2,g,p)

        print("p", user2.p)
        print("g", user2.g)
        pub_key= user2.gen() # public key

        R = user2.decode_public_key(client_key) # secret exchange key
        print("generated secret key")

        r2 = l2b(pub_key)
        P_encrypt = AES.new(pwd.ljust(16).encode(), AES.MODE_CBC)
        ct_bytes = P_encrypt.encrypt(pad(r2, AES.block_size))
        iv_encrypt = P_encrypt.iv
        ct = b64e(ct_bytes)

        # send public key to client
        self.send_json(enc_pub_key=ct, iv=b64e(iv_encrypt))
        print("client's public key is", client_key)
        print("server's public key is", pub_key)
        print("secret key is",R)

        # receive encrypted challengeA and generate challengeB
        self.recv_json()
        challengeA = user2.decrypt_string(self.data["challenge_a"], R)
        print(challengeA)
        challengeB = "byebye"

        # send challengeA + challengeB
        self.send_json(challenge_response=user2.encrypt_string(challengeA+challengeB, R))

        # receive challengeB back again
        self.recv_json()
        success = user2.decrypt_string(self.data["challenge_b"], R) == challengeB

        self.send_json(success=success)
        self.R = R

    def receive_message(self):
        self.recv_json()
        assert self.data["action"] == "send_message"
        message = self.data["message"] # no decryption for now
        print(f"[EKEHandler.receive_message] message=\"{message}\"")


def main():
    HOST = os.getenv("HOST", "localhost")
    PORT = int(os.getenv("PORT", "12345"))
    DEBUG = int(os.getenv("DEBUG", "0"))

    EKEHandler.debug_recv = DEBUG & 1 == 1
    EKEHandler.debug_send = DEBUG & 2 == 2

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((HOST, PORT), EKEHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
