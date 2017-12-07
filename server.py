#!/usr/bin/python

import argparse
import socket
import pickle
import threading
import sys
import zmq
import crypto
import json
from random import randint
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends.interfaces import DHBackend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
print_lock = threading.Lock()


users = {
        'bob': '123456',
        'alice': 'alice123',
        'carole': 'ca123'
}

# store registered users in a dictionary
logged_ident_keys = dict()
logged_ident_user = dict()


def handler(sock, s_public_key, s_private_key):
    while True:

        message = socket.recv_multipart()

        ident = message[0]  # Get which user is sending
        cmd = message[1]    # Get command from user

        if cmd == 'CONNECT':
            print 'User Attempt Login'
            # Make DH-Key, then verfiy.
            # print ident
            connect_user(sock, s_public_key, s_private_key, message)
        elif cmd == 'LOGIN':
            # print logged_ident_keys
            if logged_ident_keys.has_key(ident):
                login_user(sock, message)
            else:
                print 'Connection Unknown!'
        else:
            print 'ERR'


        # print 'dslgnljsdnljsfn'
        # print_lock.release()
        # return


def connect_user(sock, s_public_key, s_private_key, message):
    data = message
    parameters = load_pem_parameters(data[2], backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    N1 = b'12'  #TODO: Make Random
    sock.send_multipart([message[0], public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo), N1])
    
    data = sock.recv_multipart()

    peer_public_key = load_pem_public_key(data[1], backend=default_backend())
    shared_key = private_key.exchange(peer_public_key)
    # The key should be of size 256, so hash DH-Key.
    shared_key = crypto.hash_256(shared_key)
    # print shared_key

    message = "%s/%s" %(N1, shared_key)
    hashed = crypto.hash_256(message)
    signed = crypto.sign(s_private_key, hashed)
    iv, encrypt, tag = crypto.symetric_encrypt(shared_key, signed, b'only auth')

    data = sock.recv_multipart()
    decrypt = crypto.symetric_decrypt(shared_key, b'only auth', data[2], data[1], data[3])

    if hashed != decrypt:
        sock.send_multipart([data[0], "Not Authenticated"])
        print 'User Not Authenticated'
        return

    sock.send_multipart([data[0], encrypt, iv, tag])
    print 'User Authenticated'

    # save ident with shared_key
    logged_ident_keys[data[0]] = shared_key
    
        
def login_user(sock, message):
    ident = message[0]
    shared_key = logged_ident_keys[ident]
    # perform login check
    print 'LOGIN CHECK'
    decrypt = crypto.symetric_decrypt(logged_ident_keys[ident], b'only auth', message[3], message[2], message[4])

    credintials = json.loads(decrypt)

    username = credintials['user']
    passwd = credintials['passwd']
    if username in users:
        if users[username] == passwd:
            # Login Succeeded 
            print username, ' Logged In'
            logged_ident_user[ident] = username
            # send login success
            msg = 'LOGIN ACCEPTED'
            iv, encrypt, tag = crypto.symetric_encrypt(shared_key, msg, b'only auth')
            sock.send_multipart([ident, encrypt, iv, tag])
        else:
            print 'Wrong Passwd'
            # send login error
            msg = 'WRONG PASSWORD'
            iv, encrypt, tag = crypto.symetric_encrypt(shared_key, msg, b'only auth')
            sock.send_multipart([ident, encrypt, iv, tag])
    else:
        print 'No User By This Name'
        msg = 'WRONG USER'
        iv, encrypt, tag = crypto.symetric_encrypt(shared_key, msg, b'only auth')
        sock.send_multipart([ident, encrypt, iv, tag])





if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    # parser.add_argument("-sip", "--server",
    #                     default="localhost",
    #                     help="Server IP address or name")

    parser.add_argument("-sp", "--server-port", type=int,
                        default=55005,
                        help="port number of server to connect to")

    parser.add_argument("-pr", "--private-key",
                        help="private key of the server")

    parser.add_argument("-pu", "--public-key",
                        help="public key of the server")

    args = parser.parse_args()
    # PORT = args.server_port
    # SERVER_IP = args.server
    # USERNAME = args.user
    PUBLIC_KEY = args.public_key
    PRIVATE_KEY = args.private_key
    with open(PUBLIC_KEY , "rb") as key_file:
        s_public_key = serialization.load_der_public_key(
                key_file.read(),
                backend=default_backend())
    with open(PRIVATE_KEY , "rb") as key_file:
        s_private_key = serialization.load_der_private_key(
                key_file.read(),
                password=None,
                backend=default_backend())


    #  Prepare our context and sockets
    context = zmq.Context()
    # We are using the DEALER - ROUTER 
    socket = context.socket(zmq.ROUTER)
    # socket.bind("tcp://*:%s" %(args.server_port))
    socket.bind("tcp://*:55005")
    
    # sock.listen(1)
    # while True: 
        # c, addr = sock.accept()
    
    print_lock.acquire()
    t = threading.Thread(target=handler, args=(socket, s_public_key, s_private_key,))
    t.start()
    # main()