#!/usr/bin/env python

import argparse
import getpass
import os
import socket
import sys
from eke import *
from json_mixins import JsonClient
from dhmath import b64e
import random
from base64 import b64decode as b64d
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l, getPrime


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
    
    def check_user(self):
        # check with the server if the username and password entered are correct
        try:
            self.send_json(
                action="check_user",
                username=self.username,
                pwd = self.password,
                )
            self.recv_json()
            # assert self.data["success"], "Wrong Username or Password"
            if not self.data["success"]:
                print("Wrong Username or Password")
                sys.exit(-1)
        except:
            print("Exception occurred")
            sys.exit(-1)


    def exchange(self):
        # Function to generate the shared secret key

        # get diffie hellman parameters
        params = DiffieHellman.get_DH_params()
        p = params["modulus"]
        g = params["generator"]
        # get client's private key
        a1 = getPrime(2048)

        # Create user object
        user1 = DiffieHellman(a1,g,p)
        self.user = user1
        print("modulus p")
        print(hex(user1.p))
        print()
        print("generator g")
        print(hex(user1.g))
        print()
        # get client's public key
        pub_key = user1.gen()

        # P(Ea) - encrypted public key
        encrypted_pub_key, iv_encrypt = user1.encrypt(self.password.ljust(16).encode(), l2b(pub_key))

        # send encrypted public key P(Ea)
        self.send_json(
            action="negotiate",
            username=self.username,
            enc_pub_key=encrypted_pub_key,
            iv=b64e(iv_encrypt),
            modulus=user1.p,
            base = user1.g
        )

        
        self.recv_json()
        # recieve server's public key
        encrypted_client_key = b64d(self.data["enc_pub_key"])
        iv_decrypt = b64d(self.data["iv"])

        # print(DiffieHellman.salt)
        # decrypt server's public key using the password
        server_key = user1.decrypt(self.password.ljust(16).encode(), iv_decrypt, encrypted_client_key)
        server_key = b2l(server_key)

        # generate shared secret key
        dh_secret_key = user1.get_dh_exchange_key(server_key)
        # use KDF to get shared key compatible with AES
        R = user1.get_AES_key()
        self.kdf_encryption_key = R
        # print("client's public key is - ") 
        # print(hex(pub_key))
        # print()
        # print("server's public key is - ")
        # print(hex(server_key))
        # print()
        print("common secret key is - ") 
        print(hex(dh_secret_key))
        print()

        # R = l2b(R,16) # removed this because the key is now generated in bytes. Do not need to convert

        # send first encrypted challenge
        # i.e., send R(challengeA)
        challengeA = "hello"
        print("Challenge A is - ", challengeA)
        challengeA_bytes = bytes(challengeA, 'utf-8')
        encrypted_challenge_A, iv_encrypt = user1.encrypt(R ,challengeA_bytes)
        self.send_json(challenge_a=encrypted_challenge_A, iv = b64e(iv_encrypt))

        # receive challenge response
        self.recv_json()
        # decrypt R(challengeA+challengeB)
        encrypted_challenge_AB = b64d(self.data["challenge_b"])
        iv_decrypt = b64d(self.data["iv"])

        challengeAB = user1.decrypt(R, iv_decrypt, encrypted_challenge_AB)
        challengeAB = challengeAB.decode('utf-8')
        # print("challenge response - ", challengeAB)

        # check challenge A
        challengeA_decrypted = (challengeAB[:10]).strip()
        assert challengeA_decrypted == challengeA, "Challenge A failed."

        # get challengeB
        challengeB = challengeAB[10:].strip()
        print("Challenge B was - ",challengeB)

        # response with challengeB
        # i.e., send R(challengeB)
        challengeB = bytes(challengeB, 'utf-8')
        encrypted_challenge_B, iv_encrypt = user1.encrypt(R, challengeB)
        self.send_json(challenge_b=encrypted_challenge_B, iv = b64e(iv_encrypt))

        # receive success message
        self.recv_json()
        assert self.data["success"], self.data.get("message", "ChallengeB failed.")

        # store the shared key
        self.R = R

    def send_message(self, message: str):

        # encrypt message using shared secret key and send to server
        message_bytes = bytes(message, 'utf-8')
        encoded_message, iv_encrypt = self.user.encrypt(self.kdf_encryption_key ,message_bytes)

        self.send_json(
            action="send_message",
            message=encoded_message,
            iv = b64e(iv_encrypt),
            username = self.username
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
    if action not in ["register", "exchange"]:
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
                # validate the user and generate the shared key. Also allow client to sendmessage to the server.
                eke.check_user()
                eke.exchange()
                msg = input("Send message to server: ")
                eke.send_message(msg)
                print("Message encrypted and sent")
        except KeyError:
            if "success" not in eke.data:
                # raise
                print("Something went wrong")
            
            else:
                success = eke.data["success"]
                if "message" in eke.data:
                    message = eke.data["message"]
                    print(f"Caught exception: {success = } - {message}")
                else:
                    print(f"Caught exception: success={success}")


if __name__ == "__main__":
    main()
