#!/usr/bin/python

import sys
import argparse
import socket
import pickle
import select
import uuid
from random import randint
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import PublicFormat
class MainHandler:
    """Handles dispatching messages and user input

    This function takes in external events of messages and user input.
    It then dispatches those events to their appropriate handler classes.
    Finally it tracks messages and responses for getting a user before,
    a direct client to client message

    Attributes:
        server_ip: ip of server that tracks client connect information
        server_port: port of client tracking server (same as server_ip)
        username: this clients username
        sock: UDP socket
        server_sock: a shortcut tuple for socket configuration
        listening_sockets: list of sockets for select call
        message_dict: dictionary that maps FIND requests to their
            subsequent responses, for use by the client to client
            call that must get user information before it gets called



    """

    def __init__(self, server_ip, server_port, username):
        """Initializes class MainHandler
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.username = username
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.parameters = dh.generate_parameters(generator=2, key_size=1024,
                                                 backend=default_backend())
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        self.peer_public_key = ''
        self.pn = self.parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)

    def start(self):
        """Starts the MainHandler event loop

        Logs in the client with the server and then, kicks off
        an infinite while loop to handle received messages and user input.
        Tracks requests made during an attempt to do client to client
        messaging, allows us to get client ip/port then kick off a
        pseudo-callback that actually fires off the client to client message.
        Also binds the socket to a random port number between 40k and 60k.


        """
        self.sock.connect(('0.0.0.0', 55005))
        self.sock.send(self.pn)
        data = self.sock.recv(2048)
        self.peer_public_key = load_pem_public_key(data, backend=default_backend())
        self.sock.send(self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        shared_key = self.private_key.exchange(self.peer_public_key)
        print shared_key
   


def main():
    """Gets command line arguments and starts MainHandler

        Main is the function that is run when this file is called.
        It retreives the server-ip, server-port, and username from
        the command line flags.  These arguments are then passed to
        an instance of MainHandler, and the MainHandler instance has
        its' start method called.
    """
    # parser = argparse.ArgumentParser()
    # parser.add_argument("-sip")
    # parser.add_argument("-sp")
    # parser.add_argument("-u")
    # args = parser.parse_args()
    # PORT = args.sp
    # SERVER_IP = args.sip
    # USERNAME = args.u
    mh = MainHandler('localhost', 55005, 'bob')
    mh.start()

if __name__ == '__main__':
    main()
