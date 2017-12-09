#!/usr/bin/python

import argparse
import socket
import pickle
import threading
import sys
import zmq
import crypto
import json
import os
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

# list of registered users
users = {
        'bob': '123456',
        'alice': 'alice123',
        'carole': 'ca123',
        'ibrahim': '123123',
        'matt': '321321'
}

# store registered users in a dictionary
logged_ident_keys = dict()  # Saves shared key with each connection
logged_ident_user = dict()  # Saves logged user with each connection
logged_user_ident = dict()  # Saves logged user with each connection
logged_user_pukey = dict()  # Saves each user public key
logged_user_ip = dict()     # Saves each user ip
logged_user_port = dict()   # Saves each user port

def handler(sock, s_public_key, s_private_key):
    # listen for incoming messages
    while True:

        message = socket.recv_multipart()

        ident = message[0]  # Get identity of which user is sending
        cmd = message[1]    # Get command from user

        if cmd == 'CONNECT':
            print 'User Attempt Login'
            # Make DH-Key, then verfiy.
            connect_user(sock, s_public_key, s_private_key, message)
        elif cmd == 'LOGIN':
            # user trying to login
            # check if already CONNECT or not
            if logged_ident_keys.has_key(ident):
                login_user(sock, message)
            else:
                print 'Connection Unknown!'
        elif cmd == 'CMD':
            # User want some info
            # check if he is CONNECTED
            if logged_ident_keys.has_key(ident):
                # check if he is LOGGED IN
                if logged_ident_user.has_key(ident):
                    shared_key = logged_ident_keys[ident]
                    decrypt = crypto.symetric_decrypt(shared_key, b'only auth', message[3], message[2], message[4])

                    if decrypt == 'LIST':
                        print 'user want list'
                        list_command(sock, ident)
                    elif decrypt == 'LOGOUT':
                        print 'user want logout'
                        lougout_command(sock, ident)
                else:
                    print 'User not logged in!'
            else:
                print 'Connection Unknown!'

        elif cmd == 'CMDS':
            # check if he is CONNECTED
            if logged_ident_keys.has_key(ident):
                # check if he is LOGGED IN
                if logged_ident_user.has_key(ident):
                    print 'user want to send'
                    send_command(sock, ident, message)
                else:
                    print 'User not logged in!'
            else:
                print 'Connection Unknown!'
        else:
            print 'Uknown Attempt'




def send_command(sock, ident, message):
    # print 'send cmd'
    # get the shared_key
    shared_key = logged_ident_keys[ident]
    decrypt = crypto.symetric_decrypt(logged_ident_keys[ident], b'only auth', message[3], message[2], message[4])

    msg = json.loads(decrypt)

    client = msg['client']  # get name of client the user wants

    # check if client logged in:
    if not logged_user_ident.has_key(client):
        # User not there!
        reply = 'NO USER'
        iv, encrypt, tag = crypto.symetric_encrypt(shared_key, reply, b'only auth')
        sock.send_multipart([ident, encrypt, iv, tag])
        return

    # Create a random key between client-client
    key = os.urandom(256)
    key = crypto.hash_256(key)
    key = key.encode('base-64')

    # get user info and public key of both clients
    user = logged_ident_user[ident]
    u_public_key = logged_user_pukey[user]
    c_public_key = logged_user_pukey[client]
    u_public_key = u_public_key.decode('base-64')
    c_public_key = c_public_key.decode('base-64')

    # get ticket to client, 
    # TODO: Protocol change, send username with ticket
    ticket = {
        'user': user,
        'ip': logged_user_ip[user],
        'port': logged_user_port[user],
        'public_key': u_public_key.encode('base-64'),
        'key': key
    }   
    c_ident = logged_user_ident[client]
    shared_key_c2 = logged_ident_keys[c_ident]
    # encrypt ticket symmetrically using server-client2 key
    iv_ticket, encrypt_ticket, tag_ticket = crypto.symetric_encrypt(shared_key_c2, json.dumps(ticket), b'only auth')

    ticket_info = {
        'ticket': encrypt_ticket.encode('base-64'),
        'iv': iv_ticket.encode('base-64'),
        'tag': tag_ticket.encode('base-64')
    }

    # print logged_user_port

    # reply to user
    reply = {
            'client' : client,
            'ip': logged_user_ip[client],
            'port': logged_user_port[client],
            'public_key': c_public_key.encode('base-64'),
            'key': key,
            'ticket': json.dumps(ticket_info)
        }
    iv, encrypt, tag = crypto.symetric_encrypt(shared_key, json.dumps(reply), b'only auth')
    sock.send_multipart([ident, encrypt, iv, tag])



def list_command(sock, ident):
    print 'Sending list ...'

    list_users = ""
    for i in logged_ident_user:
        if i != ident:
            list_users = list_users + logged_ident_user[i] + ", "

    if list_users == "":
        list_users = "No logged in users at this moment! Try again later."

    shared_key = logged_ident_keys[ident]
    # print list_users
    iv, encrypt, tag = crypto.symetric_encrypt(shared_key, list_users.encode('ascii'), b'only auth')
    sock.send_multipart([ident, encrypt, iv, tag])

def lougout_command(sock, ident):
    # User want to logout
    shared_key = logged_ident_keys[ident]
    user = logged_ident_user[ident]

    # delete user saved info
    del logged_ident_keys[ident]
    del logged_ident_user[ident]
    del logged_user_ident[user]
    del logged_user_pukey[user] 
    del logged_user_ip[user]
    del logged_user_port[user]
    iv, encrypt, tag = crypto.symetric_encrypt(shared_key, 'LOGOUT SUCCESS', b'only auth')
    sock.send_multipart([ident, encrypt, iv, tag])
    print user, 'Logged-out'




def connect_user(sock, s_public_key, s_private_key, message):
    # establish DH key between client and server
    data = message
    parameters = load_pem_parameters(data[2], backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    
    N1 = os.urandom(16).encode('base-64')
    sock.send_multipart([message[0], public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo), N1])
    
    data = sock.recv_multipart()

    peer_public_key = load_pem_public_key(data[1], backend=default_backend())
    shared_key = private_key.exchange(peer_public_key)
    # The key should be of size 256, so hash DH-Key.
    shared_key = crypto.hash_256(shared_key)
    # shared_key is the DH-Key hash

    
    message = "%s/%s" %(N1, shared_key)
    hashed = crypto.hash_256(message)
    signed = crypto.sign(s_private_key, hashed)
    iv, encrypt, tag = crypto.symetric_encrypt(shared_key, signed, b'only auth')

    data = sock.recv_multipart()
    decrypt = crypto.symetric_decrypt(shared_key, b'only auth', data[2], data[1], data[3])

    # check returned from client, if the hash of shaared_key and N1 is correct, proceed

    if hashed != decrypt:
        sock.send_multipart([data[0], "Not Authenticated"])
        print 'User Not Authenticated'
        return

    # send the shared_key with Random N signed with server private key, 
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
    u_public_key = credintials['public_key']
    ip = credintials['ip']
    port = credintials['port']

    # check if user exists
    if username in users:
        if users[username] == passwd:
            # Login Succeeded 
            print username, 'Logged-in'
            logged_ident_user[ident] = username
            logged_user_ident[username] = ident
            logged_user_pukey[username] = u_public_key
            logged_user_ip[username] = ip
            logged_user_port[username] = port
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
                        required=True,
                        help="private key of the server")

    parser.add_argument("-pu", "--public-key",
                        required=True,
                        help="public key of the server")

    args = parser.parse_args()
    PORT = args.server_port
    # SERVER_IP = args.server
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
    socket.bind("tcp://*:%s" %(PORT))
    
    # Begin listening 
    print_lock.acquire()
    t = threading.Thread(target=handler, args=(socket, s_public_key, s_private_key,))
    t.start()
