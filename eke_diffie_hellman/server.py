#!/usr/bin/env python

import socketserver
import os
from base64 import b64encode
from eke import *
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
from json_mixins import JsonServerMixin
from primes import gen_prime


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
        # decrypt Ea using P
        # P = AES.new(self.database[self.data["username"]].ljust(16).encode(), AES.MODE_ECB)
    
        e = (self.data["enc_pub_key"])
        p = (self.data["modulus"])
        g = (self.data["base"])
        a2 = gen_prime(1000,3000) # secret key
        user2 = DiffieHellman(a2,g,p)
        print("p", user2.p)
        print("g", user2.g)
        r2 = user2.gen() # public key

        R = user2.decode_public_key(e) # secret exchange key
        print("generated secret key")
        self.send_json(enc_public_key=r2)
        print("secret key is",R)

        # generate secret key R
        # R = randbytes(16)
        # Ea = RSA.from_pub_key(e, self.data["modulus"])
        # self.send_json(enc_secret_key=b64e(P.encrypt(l2b(Ea.encrypt(b2l(R))))))
        # x = b64e(P.encrypt(l2b(Ea.encrypt(b2l(R)))))

        # transform R into a cipher instance
        # R = AES.new(R, AES.MODE_ECB)

        # receive encrypted challengeA and generate challengeB
        self.recv_json()
        # challengeA = R.decrypt(b64d(self.data["challenge_a"]))
        # challengeB = randbytes(16)
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
