#!/usr/bin/env python

import socketserver
import os
from eke import *
from json_mixins import JsonServerMixin
from dhmath import b64e
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l, getPrime
from base64 import b64decode as b64d
from Crypto import Random


class EKEHandler(socketserver.BaseRequestHandler, JsonServerMixin):
    database = {}
    database_params = {}

    def handle(self):
        # handle messages from client
        self.recv_json()

        try:
            action = self.data["action"]
            if action == "register":
                self.handle_eke_register()
            elif action == "check_user":
                self.check_user()
                self.handle()
            elif action == "negotiate":
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

    def handle_eke_register(self):
        # register a user with the server
        user = self.data["username"]
        passwd = self.data["password"]

        if user in self.database:
            self.send_json(success=False, message=f"User already registered")
            return

        self.database[user] = passwd

        self.send_json(success=True, message=f"Successfully registered user {user}")

    def check_user(self):
        # check whether username and password are correct
        if self.data['username'] not in self.database:
            print("Not registered")
            self.send_json(success=False)
        elif self.database[self.data['username']] != self.data['pwd']:
            print("Incorrect password")
            self.send_json(success=False)
        else:
            self.send_json(success=True)


    def handle_eke_negotiate_key(self):
        # Function to generate the shared secret key

        # get client's public key, modulus and generator
        encrypted_client_key = b64d(self.data["enc_pub_key"])
        iv_decrypt = b64d(self.data["iv"])
        p = (self.data["modulus"])
        g = (self.data["base"])
        username = self.data["username"]
        pwd = self.database[username]

        # get server's private key
        a2 = getPrime(2048)
        # create server object
        user2 = DiffieHellman(a2,g,p)
        # decrypt client's public key using the shared password
        client_key = user2.decrypt(pwd.ljust(16).encode(), iv_decrypt, encrypted_client_key)
        client_key = b2l(client_key)

        print("modulus p")
        print(hex(user2.p))
        print()
        print("generator g")
        print(hex(user2.g))
        print()

        # get server's public key
        pub_key= user2.gen()

        # generate the shared secret key 
        dh_secret_key = user2.get_dh_exchange_key(client_key)

        print("common secret key is - ") 
        print(hex(dh_secret_key))
        print()

        # use KDF to get shared key compatible with AES
        R = user2.get_AES_key()
        self.database_params[username] = (user2, R)

        encrypted_pub_key, iv_encrypt = user2.encrypt(pwd.ljust(16).encode(), l2b(pub_key))

        # send public key to client
        self.send_json(enc_pub_key=encrypted_pub_key, iv=b64e(iv_encrypt))
        # print("client's public key is", client_key)
        # print("server's public key is", pub_key)
        
        # R = l2b(R,16) # removed this because the key is now generated in bytes. Do not need to convert

        # receive encrypted challengeA and generate challengeB
        self.recv_json()
        encypted_challenge_A = b64d(self.data["challenge_a"])
        iv_decrypt = b64d(self.data["iv"])
        # decrypt using secret key
        challengeA = user2.decrypt(R, iv_decrypt, encypted_challenge_A)
        challengeA = challengeA.decode('utf-8')
        print("Challenge A was - ", challengeA)

        # send challenge A + challenge B
        challengeB = "byebye"
        print("Challenge B is - ", challengeB)
        challengeAB = challengeA.ljust(10) + challengeB.ljust(10)
        challengeAB = bytes(challengeAB, 'utf-8')
        encrypted_challenge_B, iv_encrypt = user2.encrypt(R, challengeAB)
        self.send_json(challenge_b=encrypted_challenge_B, iv = b64e(iv_encrypt))

        # receive challengeB back
        self.recv_json()
        encrypted_challenge_B = b64d(self.data["challenge_b"])
        iv_decrypt = b64d(self.data["iv"])

        challengeB_decrypted = user2.decrypt(R, iv_decrypt, encrypted_challenge_B)
        challengeB_decrypted = challengeB_decrypted.decode('utf-8')
        success = challengeB_decrypted == challengeB
        # return success if challengeB is the same
        self.send_json(success=success)
        self.R = R

    def receive_message(self):
        # decrypt the message received from the client
        self.recv_json()
        assert self.data["action"] == "send_message"
        username = self.data["username"]
        encrypted_message = b64d(self.data["message"])
        iv_decrypt = b64d(self.data["iv"])
        user, R = self.database_params[username]
        message_decrypted = user.decrypt(R, iv_decrypt, encrypted_message)
        message_decrypted = message_decrypted.decode('utf-8')

        print(f"Received message from user {username}=\"{message_decrypted}\"")


def main():
    HOST = os.getenv("HOST", "localhost")
    PORT = int(os.getenv("PORT", "12345"))
    DEBUG = int(os.getenv("DEBUG", "0"))

    EKEHandler.debug_recv = DEBUG & 1 == 1
    EKEHandler.debug_send = DEBUG & 2 == 2

    socketserver.TCPServer.allow_reuse_address = True
    try:
        with socketserver.TCPServer((HOST, PORT), EKEHandler) as server:
            server.serve_forever()
    except:
        print("Ending server program")
        quit()


if __name__ == "__main__":
    main()
