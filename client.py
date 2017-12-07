#!/usr/bin/python

import sys
import argparse
import socket
import pickle
import select
import uuid
import zmq
import crypto
import json
from random import randint
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
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

    def __init__(self, server_ip, server_port, username, s_public_key):
        """Initializes class MainHandler
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.username = username
        self.s_public_key = s_public_key
        #  Prepare our context and sockets
        context = zmq.Context()

        # We are using the DEALER
        self.sock = context.socket(zmq.DEALER)
        # self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        

        
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
        # self.sock.connect("tcp://%s:%s" %(self.server_ip, self.server_port))
        self.sock.connect("tcp://0.0.0.0:55005")
        # self.sock.connect(('0.0.0.0', 55005))

        self.sock.send_multipart(['CONNECT', self.pn])
        # data = self.sock.recv(2048)
        # print 'wait'
        data = self.sock.recv_multipart()
        # print data 

        self.peer_public_key = load_pem_public_key(data[0], backend=default_backend())
        self.sock.send(self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        shared_key = self.private_key.exchange(self.peer_public_key)
        #TODO: The key should be of size 256, so hash DH-Key.
        shared_key = crypto.hash_256(shared_key)
        # print shared_key

        N1 = data[1]
        message = "%s/%s" %(N1, shared_key)
        hashed = crypto.hash_256(message)
        iv, encrypt, tag = crypto.symetric_encrypt(shared_key, hashed, b'only auth')
        self.sock.send_multipart([encrypt, iv, tag])

        data = self.sock.recv_multipart()
        # print data[0]
        if data[0] == "Not Authenticated":
            print "DROP CONNECTION"
            # exit
        decrypt = crypto.symetric_decrypt(shared_key, b'only auth', data[1], data[0], data[2])
        # signed_hashed = json.loads(decrypt)
        verify = crypto.verify(self.s_public_key, decrypt, hashed)
        if not verify:
            print 'Error Connecting to Server'
            #exit
        print 'Connected To Server'
        
        #Prompt for password
        # print ''
        try:
            user_request = raw_input('Enter your password:')
        except KeyboardInterrupt:
            print 'ERROR'
            # exit()
        user_request = map(str, user_request.split(' '))
        passwd = user_request[0]
        credintials = {
            'user' : self.username,
            'passwd': passwd
        }
        # TODO: Send user_public_key with the login message
        iv, encrypt, tag = crypto.symetric_encrypt(shared_key, json.dumps(credintials), b'only auth')
        self.sock.send_multipart(['LOGIN', encrypt, iv, tag])

    



   


def main():
    """Gets command line arguments and starts MainHandler
        Main is the function that is run when this file is called.
        It retreives the server-ip, server-port, and username from
        the command line flags.  These arguments are then passed to
        an instance of MainHandler, and the MainHandler instance has
        its' start method called.
    """
    parser = argparse.ArgumentParser()
    # parser.add_argument("-sip", "--server",
    #                     default="localhost",
    #                     help="Server IP address or name")

    # parser.add_argument("-sp", "--server-port", type=int,
    #                     default=5569,
    #                     help="port number of server to connect to")

    # parser.add_argument("-u", "--user",
    #                     default="Alice",
    #                     help="name of user")

    parser.add_argument("-pus", "--public-key-server",
                        help="public key of the server")

    args = parser.parse_args()
    PUBLIC_KEY = args.public_key_server
    with open(PUBLIC_KEY , "rb") as key_file:
        s_public_key = serialization.load_der_public_key(
                key_file.read(),
                backend=default_backend())
    # PORT = args.server_port
    # SERVER_IP = args.server
    # USERNAME = args.user

    mh = MainHandler('localhost', 55005, 'bob', s_public_key)
    mh.start()

if __name__ == '__main__':
    main()