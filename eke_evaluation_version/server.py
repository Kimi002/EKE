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
    # creating test user
    database["dummy_user"] = "dummy_pwd"

    def handle(self):
        self.recv_json()

        try:
            action = self.data["action"]
            if action == "register":
                self.handle_eke_register()
            elif self.data['username'] not in self.database:
                print("Not registered")
            elif action == "negotiate":
                self.handle_eke_negotiate_key()
                # self.receive_message()
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

        # set the salt which is later used for key derivation
        # salt = os.urandom(16)
        # DiffieHellman.salt = salt

        # get client's public key, p and g
        encrypted_client_key = b64d(self.data["enc_pub_key"])
        iv_decrypt = b64d(self.data["iv"])
        p = (self.data["modulus"])
        g = (self.data["base"])
        pwd = self.database[self.data["username"]]

        a2 = getPrime(2048) # secret key
        user2 = DiffieHellman(a2,g,p)
        client_key = user2.decrypt(pwd.ljust(16).encode(), iv_decrypt, encrypted_client_key)
        client_key = b2l(client_key)

        # print("p", user2.p)
        # print("g", user2.g)
        pub_key= user2.gen() # public key

        dh_secret_key = user2.get_dh_exchange_key(client_key)
        # print()
        # print(DiffieHellman.salt)
        # print()

        encrypted_pub_key, iv_encrypt = user2.encrypt(pwd.ljust(16).encode(), l2b(pub_key))

        # send public key to client
        self.send_json(enc_pub_key=encrypted_pub_key, iv=b64e(iv_encrypt))
        # print("client's public key is", client_key)
        # print("server's public key is", pub_key)
        print("common secret key is")
        print(dh_secret_key)

        self.R = dh_secret_key

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
    try:
        with socketserver.TCPServer((HOST, PORT), EKEHandler) as server:
            server.serve_forever()
    except:
        print("Ending server program")
        quit()


if __name__ == "__main__":
    main()
