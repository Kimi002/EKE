#!/usr/bin/env python

import argparse
import getpass
import os
import socket
import sys
from eke import *
from json_mixins import JsonClient
from primes import gen_prime, b64e
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode as b64d
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l


class EKE(JsonClient):
    def __init__(self, username, password, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.username = username
        self.password = password


    def register(self):
        # send a register command
        self.send_json(action="register", username=self.username, password=self.password)

        # receive the status back
        self.recv_json()
        if self.data["success"]:
            print(self.data["message"])
        else:
            print("Failed to register user.")


    def negotiate(self):
        # generate random public key Ea
        p = gen_prime(2000,6000)
        g = gen_prime(500,1000)
        a1 = gen_prime(1000,3000) # secret key
        user1 = DiffieHellman(a1,g,p)
        print("p", user1.p)
        print("g", user1.g)
        pub_key = user1.gen() # public key

        # Encyption object
        P_encrypt = AES.new(self.password.ljust(16).encode(), AES.MODE_CBC)

        # # P(Ea)
        # r1 = b64e(P.encrypt(l2b(r1)))

        r1 = l2b(pub_key)
        ct_bytes = P_encrypt.encrypt(pad(r1, AES.block_size))
        iv_encypt = P_encrypt.iv
        ct = b64e(ct_bytes)
        print("iv",P_encrypt.iv)

        # send public key P(Ea)
        self.send_json(
            action="negotiate",
            username=self.username,
            enc_pub_key=ct,
            iv=b64e(iv_encypt),
            modulus=user1.p,
            base = user1.g
        )

        
        self.recv_json()
        # recieve public key
        encypted_client_key = b64d(self.data["enc_pub_key"])
        iv_decrypt = b64d(self.data["iv"])

        P_decrypt = AES.new(self.password.ljust(16).encode(), AES.MODE_CBC, iv_decrypt)
        server_key = b2l(unpad(P_decrypt.decrypt(encypted_client_key), AES.block_size))


        R = user1.decode_public_key(server_key) # secret exchange key
        print("client's public key is", pub_key)
        print("server's public key is", server_key)
        print("common secret key",R)

        # send first challenge
        # send R(challengeA)
        # encyption object with common secret key
        R = l2b(R,16)
        iv_encrypt = Random.get_random_bytes(16)
        R_encrypt = AES.new(R, AES.MODE_CBC, iv_encrypt)
        challengeA = "hello"
        challengeA_bytes = bytes(challengeA, 'utf-8')
        encrypted_challenge_A = R_encrypt.encrypt(pad(challengeA_bytes, AES.block_size))
        self.send_json(challenge_a=b64e(encrypted_challenge_A), iv = b64e(iv_encrypt))

        # receive challenge response
        self.recv_json()
        # decrypt R(challengeA+challengeB)
        encypted_challenge_AB = b64d(self.data["challenge_b"])
        iv_decrypt = b64d(self.data["iv"])

        R_decrypt = AES.new(R, AES.MODE_CBC, iv_decrypt)
        challengeAB = unpad(R_decrypt.decrypt(encypted_challenge_AB), AES.block_size)
        challengeAB = challengeAB.decode('utf-8')
        print("challenge response", challengeAB)

        # check challenge A
        challengeA_decrypted = (challengeAB[:10]).strip()
        assert challengeA_decrypted == challengeA, "Challenge A failed."

        # get challengeB
        challengeB = challengeAB[10:].strip()
        print(challengeB)

        # response with challengeB
        #send R(challengeB)
        iv_encrypt = Random.get_random_bytes(16)
        R_encrypt = AES.new(R, AES.MODE_CBC, iv_encrypt)
        challengeB = bytes(challengeB, 'utf-8')
        encrypted_challenge_B = R_encrypt.encrypt(pad(challengeB, AES.block_size))
        self.send_json(challenge_b=b64e(encrypted_challenge_B), iv = b64e(iv_encrypt))

        # receive success message
        self.recv_json()
        assert self.data["success"], self.data.get("message", "ChallengeB failed.")

        # store the shared key
        self.R = R

    def send_message(self, message: str):
        encoded_message = message # no encryption for now
        self.send_json(
            action="send_message",
            message=encoded_message,
        )
    


def main():
    DEFAULT_HOST = os.getenv("HOST", "localhost")
    DEFAULT_PORT = int(os.getenv("PORT", "12345"))

    parser = argparse.ArgumentParser(description="Client for EKE.")
    parser.add_argument("action",   help="The action to perform (register|negotiate)")
    parser.add_argument("--host",   help="The host to connect to.", default=DEFAULT_HOST)
    parser.add_argument("--port",   help="The port to connect to.", default=DEFAULT_PORT, type=int)
    parser.add_argument("--user",   help="The username to use in the protocol.")
    parser.add_argument("--passwd", help="The password to use in the protocol.")
    parser.add_argument("--debug",  help="Enable debug logging", default=0, type=int)

    args = parser.parse_args()
    HOST = args.host
    PORT = args.port

    debug_recv = args.debug & 1 == 1
    debug_send = args.debug & 2 == 2

    action = args.action
    if action not in ["register", "negotiate"]:
        print(f"Unrecognised action: \"{action}\"")
        sys.exit(-1)

    username = args.user if args.user else input("Username: ")
    password = args.passwd if args.passwd else getpass.getpass("Password: ")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))

        eke = EKE(
            username,
            password,
            conn=sock,
            debug_send=debug_send,
            debug_recv=debug_recv
        )

        try:
            if action == "register":
                eke.register()
            else:
                eke.negotiate()
                msg = input("message: ")
                eke.send_message(msg)
        except KeyError:
            if "success" not in eke.data:
                raise

            success = eke.data["success"]
            if "message" in eke.data:
                message = eke.data["message"]
                print(f"Caught exception: {success = } - {message}")
            else:
                print(f"Caught exception: success={success}")


if __name__ == "__main__":
    main()
