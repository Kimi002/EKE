#!/usr/bin/env python

import argparse
import socketserver
import os
from eke import *
from json_mixins import JsonServerMixin
from dhmath import b64e, int_to_base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l, getPrime
from base64 import b64decode as b64d
from Crypto import Random
import sys


class EKEHandler(socketserver.BaseRequestHandler, JsonServerMixin):
    server_password = ""
    exchange_key = ""
    user = None

    def handle(self):
        # handle messages from client
        self.recv_json()

        try:
            action = self.data["action"]
            if action == "negotiate":
                self.handle_eke_negotiate_key()
                self.receive_message()
            else:
                self.send_json(error=f"Unrecognised action: {action}")
        except KeyError:
            if "success" not in self.data:
                # raise
                print("Something went wrong")
            
            else:
                success = self.data["success"]
                if "message" in self.data:
                    message = self.data["message"]
                    print(f"Caught exception: {success = } - {message}")
                else:
                    print(f"Caught exception: success={success}")


    def handle_eke_negotiate_key(self):
        # Function to generate the shared secret key

        # get client's public key, modulus and generator
        encrypted_client_key = b64d(self.data["enc_pub_key"])
        iv_decrypt = b64d(self.data["iv"])
        p = (self.data["modulus"])
        g = (self.data["base"])
        pwd = EKEHandler.server_password

        # get server's private key
        a2 = getPrime(2048)
        # create server object
        user2 = DiffieHellman(a2,g,p)
        # decrypt client's public key using the shared password
        client_key = user2.decrypt(pwd.ljust(16).encode(), iv_decrypt, encrypted_client_key)
        client_key = b2l(client_key)

        print("modulus p")
        print(int_to_base64(user2.p))
        print()
        print("generator g")
        print(int_to_base64(user2.g))
        print()

        # get server's public key
        pub_key= user2.gen()

        # generate the shared secret key 
        dh_secret_key = user2.get_dh_exchange_key(client_key)

        print("common secret key is - ") 
        print(int_to_base64(dh_secret_key))
        print()

        # use KDF to get shared key compatible with AES
        R = user2.get_AES_key()
        EKEHandler.exchange_key = R
        EKEHandler.user = user2

        encrypted_pub_key, iv_encrypt = user2.encrypt(pwd.ljust(16).encode(), l2b(pub_key))

        # send public key to client
        self.send_json(enc_pub_key=encrypted_pub_key, iv=b64e(iv_encrypt))
        # print("client's public key is", client_key)
        # print("server's public key is", pub_key)
        
        # R = l2b(R,16) # removed this because the key is now generated in bytes. Do not need to convert

        # receive encrypted challengeA and generate challengeB
        # self.recv_json()
        # encypted_challenge_A = b64d(self.data["challenge_a"])
        # iv_decrypt = b64d(self.data["iv"])
        # # decrypt using secret key
        # challengeA = user2.decrypt(R, iv_decrypt, encypted_challenge_A)
        # try:
        #     challengeA = challengeA.decode('utf-8')
        #     A_success = True
        # except:
        #     print("Could not decrypt challenge A to text")
        #     A_success = False
        # print("Challenge A was - ", challengeA)
        # challengeB = "byebye"
        # print("Challenge B is - ", challengeB)

        # # send challenge A + challenge B
        # if A_success:
        #     challengeAB = challengeA.ljust(10) + challengeB.ljust(10)
        #     challengeAB = bytes(challengeAB, 'utf-8')
        #     encrypted_challenge_B, iv_encrypt = user2.encrypt(R, challengeAB)
        # else:
        #     challengeA_bytes = challengeA
        #     challengeB_bytes = bytes(challengeB, 'utf-8')

        #     # Padding both challenges separately to a length of 10 bytes
        #     challengeA_padded = challengeA_bytes.ljust(10)
        #     challengeB_padded = challengeB_bytes.ljust(10)

        #     # Combine the padded challenges
        #     challengeAB_bytes = challengeA_padded + challengeB_padded

        #     # Encrypt the combined challenges
        #     encrypted_challenge_B, iv_encrypt = user2.encrypt(R, challengeAB_bytes)

        # self.send_json(challenge_b=encrypted_challenge_B, iv = b64e(iv_encrypt))

        # # receive challengeB back
        # self.recv_json()
        # encrypted_challenge_B = b64d(self.data["challenge_b"])
        # iv_decrypt = b64d(self.data["iv"])

        # challengeB_decrypted = user2.decrypt(R, iv_decrypt, encrypted_challenge_B)
        # try:
        #     challengeB_decrypted = challengeB_decrypted.decode('utf-8')
        # except:
        #     print("Could not decrypt response to challengeB")
        # success = challengeB_decrypted == challengeB
        # if success:
        #     print("Challenge succeeded")
        # else:
        #     print("Challenge failed")
        # return success if challengeB is the same
        # self.send_json(success=success)
        self.R = R

    def receive_message(self):
        # decrypt the message received from the client
        self.recv_json()
        assert self.data["action"] == "send_message"
        # username = self.data["username"]
        encrypted_message = b64d(self.data["message"])
        iv_decrypt = b64d(self.data["iv"])
        # user, R = self.database_params[username]
        R = EKEHandler.exchange_key
        user = EKEHandler.user
        message_decrypted = user.decrypt(R, iv_decrypt, encrypted_message)
        message_decrypted = message_decrypted.decode('utf-8')

        print(f"Received message from user=\"{message_decrypted}\"")


def main():
    HOST = os.getenv("HOST", "localhost")
    PORT = int(os.getenv("PORT", "12345"))
    DEBUG = int(os.getenv("DEBUG", "0"))

    parser = argparse.ArgumentParser(description="Client for EKE.")
    parser.add_argument("--passwd", help="The password to use in the protocol.")

    EKEHandler.debug_recv = DEBUG & 1 == 1
    EKEHandler.debug_send = DEBUG & 2 == 2

    socketserver.TCPServer.allow_reuse_address = True

    args = parser.parse_args()
    pwd = args.passwd if args.passwd else input("Password: ")
    EKEHandler.server_password = pwd

    try:
        with socketserver.TCPServer((HOST, PORT), EKEHandler) as server:
            server.serve_forever()
    except:
        print("Ending server program")
        quit()


if __name__ == "__main__":
    main()
