#!/usr/bin/python

import sys
import os
import argparse
import socket
import pickle
import select
import uuid
import zmq
import crypto
import threading
import json
from random import randint
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import PublicFormat

NOT_LOGGED_IN = 0
LOGGED_IN = 1
status = 0

CLIENT_IP = '127.0.0.1' # localhost
CLIENT_PORT = 0 # random port number.


# for user
connected_user_keys = dict()  # Saves shared key with each connection
connected_ident_user = dict()  # Saves connected user with each connection
connected_user_pukey = dict()  # Saves each user public key
connected_user_ip = dict()     # Saves each user ip
connected_user_port = dict()   # Saves each user port

connected_user_sock = dict()


def lestining(u_private_key, u_public_key, USERNAME):
    '''
    This thread listens to connection to client on some port.
    '''
    global CLIENT_IP
    global CLIENT_PORT
    # this thread lestins for incoming connections
    #  Prepare our context and sockets
    context = zmq.Context()
    # We are using the DEALER - ROUTER 
    socket = context.socket(zmq.ROUTER)
    # socket.bind("tcp://*:%s" %(args.server_port))
    CLIENT_PORT = socket.bind_to_random_port("tcp://%s" %(CLIENT_IP))
    print 'Client listening on port:', CLIENT_PORT

    while True:
        message = socket.recv_multipart()

        ident = message[0]  # Get which user is sending
        cmd = message[1]


        if cmd == 'CMD':
            # msg recieved
            # check if connected before
            if connected_ident_user.has_key(ident):
                client = connected_ident_user[ident]

                shared_key = connected_user_keys[client]
                c_public_key = connected_user_pukey[client]
                c_public_key = c_public_key.decode('base-64')

                c_public_key_load = serialization.load_pem_public_key(c_public_key.encode('ascii'), backend=default_backend())  

                decrypt = crypto.symetric_decrypt(shared_key, b'only auth', message[3], message[2], message[4])
                packet = json.loads(decrypt)
                msg = packet['msg'].decode('base-64')
                signed = packet['sign'].decode('base-64')

                verify = crypto.verify(c_public_key_load, signed, msg)

                # Check if verified or ignore
                if verify:
                    # print incoming message
                    print '\r<= ', client, 'sent: ', msg, '\n=>'
                    # sys.stdout.write('=> ')
                    

            continue
        
        if cmd == 'I':
            connected_ident_user[ident] = message[2]
            # print message[2] 
            continue

        try:
            encrypt_pn = message[2]
            iv_pn = message[3]
            tag_pn = message[4]
            ticket = message[5]
        except:
            continue

        server_key = connected_user_keys['server']
        server_key = server_key.decode('base-64')

        # get ticket info
        ticket_info = json.loads(json.loads(ticket))
        encrypt_ticket = ticket_info['ticket'].decode('base-64')
        iv_ticket = ticket_info['iv'].decode('base-64')
        tag_ticket = ticket_info['tag'].decode('base-64')
        decrypt_ticket = crypto.symetric_decrypt(server_key, b'only auth', iv_ticket, encrypt_ticket, tag_ticket)
        d_ticket = json.loads(decrypt_ticket)

        # get info from the ticket
        client = d_ticket['user']
        ip = d_ticket['ip']
        port = d_ticket['port']
        c_public_key_b = d_ticket['public_key']
        key = d_ticket['key']
        key = key.decode('base-64')
        
        c_public_key = c_public_key_b.decode('base-64')

        d_conn = crypto.symetric_decrypt(key, b'only auth', iv_pn, encrypt_pn, tag_pn)
        j_conn = json.loads(d_conn)
        parameters = load_pem_parameters(j_conn['pn'].decode('base-64'), backend=default_backend())
        private_key_dh = parameters.generate_private_key()
        public_key_dh = private_key_dh.public_key()

        # Random number
        N1 = os.urandom(16).encode('base-64')
        con = {
            'N1': N1,
            'public': public_key_dh.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).encode('base-64')
        }
        iv_dh, encrypt_dh, tag_dh = crypto.symetric_encrypt(key, json.dumps(con), b'only auth')
        socket.send_multipart([ident, encrypt_dh, iv_dh, tag_dh])

        peer_public_key = load_pem_public_key(j_conn['public_key_dh'].decode('base-64'), backend=default_backend())
        shared_key = private_key_dh.exchange(peer_public_key)
        # DH-Key established
        # The key should be of size 256, so hash DH-Key.
        shared_key = crypto.hash_256(shared_key)


        message = "%s/%s" %(N1.encode('ascii'), shared_key)
        hashed = crypto.hash_256(message)
        signed = crypto.sign(u_private_key, hashed)
        iv, encrypt, tag = crypto.symetric_encrypt(shared_key, signed, b'only auth')

        data = socket.recv_multipart()
        decrypt = crypto.symetric_decrypt(shared_key, b'only auth', data[2], data[1], data[3])
        c_public_key_load = serialization.load_pem_public_key(c_public_key.encode('ascii'), backend=default_backend())  
        verify = crypto.verify(c_public_key_load, decrypt, hashed)

        # print verify
        # check signatures and verify it really him
        if not verify:
            # Not verifed, Drop connection!
            socket.send_multipart([ident, 'NO'])
            # drop connection
        else:
            
            context = zmq.Context()
            s = context.socket(zmq.DEALER)
            s.connect("tcp://%s:%s" %(ip, port))
            connected_user_sock[client] = s
            s.send_multipart(['I', USERNAME])

            connected_ident_user[ident] = client
            connected_user_ip[client] = ip
            connected_user_port[client] = port
            connected_user_keys[client] = shared_key
            connected_user_pukey[client] = c_public_key_b
            socket.send_multipart([ident, encrypt, iv, tag])

            
        




class MainHandler:
    """Handles sending messages and user input
    
    """

    def __init__(self, server_ip, server_port, username, s_public_key, u_public_key, u_private_key):
        """Initializes class MainHandler
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.username = username
        self.s_public_key = s_public_key
        self.u_public_key = u_public_key
        self.u_private_key = u_private_key
        #  Prepare our context and sockets
        context = zmq.Context()
        # We are using the DEALER
        self.sock = context.socket(zmq.DEALER)        
        
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
        # connect to server
        self.sock.connect("tcp://%s:%s" %(self.server_ip, self.server_port))

        # establishing DH
        self.sock.send_multipart(['CONNECT', self.pn])

        # get DH public key of server
        data = self.sock.recv_multipart()

        self.peer_public_key = load_pem_public_key(data[0], backend=default_backend())
        self.sock.send(self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
       
        shared_key = self.private_key.exchange(self.peer_public_key)
        #The key should be of size 256, so hash DH-Key.
        shared_key = crypto.hash_256(shared_key)
        # save the shared key between CLIENT-SERVER
        connected_user_keys['server'] = shared_key.encode('base-64')

        # sends a hash of shared_key and the server's N random.
        N1 = data[1]
        message = "%s/%s" %(N1, shared_key)
        hashed = crypto.hash_256(message)
        iv, encrypt, tag = crypto.symetric_encrypt(shared_key, hashed, b'only auth')
        self.sock.send_multipart([encrypt, iv, tag])

        data = self.sock.recv_multipart()
        # check if server acceptes
        if data[0] == "Not Authenticated":
            print "DROP CONNECTION"
            self.error(self.sock, "DROPPED CONNECTION FROM SERVER", shared_key)
        
        # else server accepts
        decrypt = crypto.symetric_decrypt(shared_key, b'only auth', data[1], data[0], data[2])
        # verify if the server response is signed with server's private key and is the same hash as sent
        verify = crypto.verify(self.s_public_key, decrypt, hashed)

        if not verify:
            print 'Error Connecting to Server'
            self.error(self.sock, 'Error Connecting to Server', shared_key)
            #exit
        print '\nConnected To Server'
        
        #Prompt for password
        try:
            user_request = raw_input('Enter Your Password:')
        except KeyboardInterrupt:
            print 'KeyboardInterrupt'
            self.error(self.sock, 'KeyboardInterrupt', shared_key)

        user_request = map(str, user_request.split(' '))
        passwd = user_request[0]

        pem = self.u_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
         )

        credintials = {
            'user' : self.username,
            'passwd': passwd,
            'public_key': pem.encode('base-64'),
            'ip': CLIENT_IP,
            'port': CLIENT_PORT
        }
        
        iv, encrypt, tag = crypto.symetric_encrypt(shared_key, json.dumps(credintials), b'only auth')
        self.sock.send_multipart(['LOGIN', encrypt, iv, tag])
        
        data = self.sock.recv_multipart()
        encrypted = data[0]
        iv = data[1]
        tag = data[2]
        decrypt = crypto.symetric_decrypt(shared_key, b'only auth', iv, encrypted, tag)

        if decrypt == 'LOGIN ACCEPTED':
            print 'LOGIN SUCCESS, WELCOME', self.username
            global status
            global LOGGED_IN
            status = LOGGED_IN
            self.after_login(self.sock, shared_key, self.username)
        elif decrypt == 'WRONG PASSWORD':
            self.error(self.sock, 'Password Not Correct!', shared_key)
        elif decrypt == 'WRONG USER':
            self.error(self.sock, 'No User By This Name!', shared_key)
        else:
            self.error(self.sock, 'Unknown Login Response!', shared_key)
            



    def after_login(self, sock, shared_key, username):
        print '\n'
        # infinte loop tracks user input.
        
        print 'Supported Commands: LIST, SEND USER msg, LOGOUT'
        print 'Enter your command: '
        while True:
            try:
                user_request = raw_input('=> ')
            except KeyboardInterrupt:
                self.error(sock, 'KeyboardInterrupt', shared_key)


            user_request = map(str, user_request.split(' '))
            cmd = user_request[0]
            
            if cmd == 'LIST' or cmd == 'list':
                # print 'LIST COMMAND'
                self.list_users(sock, shared_key)


            elif cmd == 'SEND' or cmd == 'send':
                # print 'SEND'
                to = user_request[1]
                msg = user_request[2:]
                msg = ' '.join(msg)
                self.send_message(sock, shared_key, to, msg)

            elif cmd == 'LOGOUT' or cmd == 'logout':
                print 'Logging out ....'
                self.logout(sock, shared_key)

            else:
                print 'Unknown input!'
                print 'Supported Commands: LIST, SEND USER msg, LOGOUT'
            
    
    def send_message(self, sock, shared_key, client, message):
        # each client should be lestining on some port, sends his ip and port to server on login
        # Get the information to go to C2
        # establish connection with C2
        # Save shared key with C2 for some time for future messsages

        # check if already have established key with client2
        if client in connected_user_keys:
            if client in connected_user_sock:
                socket = connected_user_sock[client]
            else:
                ip = connected_user_ip[client]
                port = connected_user_port[client]
                context = zmq.Context()
                socket = context.socket(zmq.DEALER)
                socket.connect("tcp://%s:%s" %(ip, port))

            self.msg(socket, client, message)
            return
        
        
        # not connected to Client2 before, so ask server to connect to Client2 
        msg = {
                'cmd' : 'SEND',
                'client': client
            }
        iv, encrypt, tag = crypto.symetric_encrypt(shared_key, json.dumps(msg), b'only auth')
        sock.send_multipart(['CMDS', encrypt, iv, tag])

        data = sock.recv_multipart()
        decrypt = crypto.symetric_decrypt(shared_key, b'only auth', data[1], data[0], data[2])

        if decrypt == 'NO USER':
            # user not logged in or not exist
            print '<= Server Reply: User %s not logged-in or does not exist!' %(client)
            return

        reply = json.loads(decrypt)

        # reply info to client
                # REPLY CONTAINS:
                # 'client' : client,
                # 'ip': logged_user_ip[client],
                # 'port': logged_user_port[client],
                # 'public_key': c_public_key.encode('base-64'),
                # 'key': key,
                # 'ticket': json.dumps(ticket_info)
        key = reply['key']
        ip = reply['ip']
        port = reply['port']
        public_key = reply['public_key']
        ticket = reply['ticket']
        # print 'ip:port ', ip, ':', port

        connected_user_ip[client] = ip
        connected_user_port[client] = port
        connected_user_pukey[client] = public_key
        # connected_user_keys[client] = key

        # establish connection with client2
        self.connect_client(client, ticket, key, message)


    def connect_client(self, client, ticket, key, msg):
        print 'Establishing Connection ...'
        # get client info
        ip = connected_user_ip[client]
        port = connected_user_port[client]
        c_public_key = connected_user_pukey[client]
        # key = connected_user_keys[client]
        c_public_key = c_public_key.decode('base-64')

        context = zmq.Context()
        sock = context.socket(zmq.DEALER)
        sock.connect("tcp://%s:%s" %(ip, port))

        key = key.decode('base-64')

        # SEND TICKET AND DH-KEY ENCRYPTED WITH KEY
        parameters = dh.generate_parameters(generator=2, key_size=1024,
                                                    backend=default_backend())
        private_key_dh = parameters.generate_private_key()
        public_key_dh = private_key_dh.public_key()
        pn = parameters.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
        # SEND pn and public_key Encrypted with key
        conn = {
            'pn': pn.encode('base-64'),
            'public_key_dh': public_key_dh.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).encode('base-64')
        }
        iv_pn, encrypt_pn, tag_pn = crypto.symetric_encrypt(key, json.dumps(conn), b'only auth')
        sock.send_multipart(['CONNECT', encrypt_pn, iv_pn, tag_pn, json.dumps(ticket)])

        # RECIEVE FROM OTHER CLIENT
        data = sock.recv_multipart()
        encrypt_dh = data[0]
        iv_dh = data[1]
        tag_dh = data[2]
        pu_decrypt = crypto.symetric_decrypt(key, b'only auth', iv_dh, encrypt_dh, tag_dh)
        j_conn = json.loads(pu_decrypt)
        peer_public_key = load_pem_public_key(j_conn['public'].decode('base-64'), backend=default_backend())

        N1 = j_conn['N1']

        # Use DH established key for further communication
        shared_key = private_key_dh.exchange(peer_public_key)
        shared_key = crypto.hash_256(shared_key)


        message = "%s/%s" %(N1.encode('ascii'), shared_key)
        hashed = crypto.hash_256(message)
        signed = crypto.sign(self.u_private_key, hashed)
        iv, encrypt, tag = crypto.symetric_encrypt(shared_key, signed, b'only auth')
        sock.send_multipart([encrypt, iv, tag])

        data = sock.recv_multipart()
        if data[0] == 'NO':
            print "Couldn't establish connection with Client, Drop Connection!"
        else:
            decrypt = crypto.symetric_decrypt(shared_key, b'only auth', data[1], data[0], data[2])
            c_public_key_load = serialization.load_pem_public_key(c_public_key.encode('ascii'), backend=default_backend())  
            verify = crypto.verify(c_public_key_load, decrypt, hashed)
            # print verify
            # check if verification correct "signed correctly"
            if not verify:
                print "Couldn't establish connection with Client, Drop Connection!"
            else:
                # 'verified !!'
                connected_user_keys[client] = shared_key
                connected_user_sock[client] = sock
                # key established
                # send message
                print 'Connection Established!'
                self.msg(sock, client, msg)
                


    def msg(self, sock, client, msg):
        shared_key = connected_user_keys[client]
        signed = crypto.sign(self.u_private_key, msg)
        # send msg and sign it.
        packet = {
            'msg': msg.encode('base-64'),
            'sign': signed.encode('base-64')
        }
        iv, encrypt, tag = crypto.symetric_encrypt(shared_key, json.dumps(packet), b'only auth')
        sock.send_multipart(['CMD', encrypt, iv, tag])
        

    def list_users(self, sock, shared_key):
        msg = 'LIST'
        iv, encrypt, tag = crypto.symetric_encrypt(shared_key, msg, b'only auth')
        sock.send_multipart(['CMD', encrypt, iv, tag])

        data = sock.recv_multipart()
        decrypt = crypto.symetric_decrypt(shared_key, b'only auth', data[1], data[0], data[2])

        print '<= ', decrypt

    def logout(self, sock, shared_key):
        msg = 'LOGOUT'
        iv, encrypt, tag = crypto.symetric_encrypt(shared_key, msg, b'only auth')
        sock.send_multipart(['CMD', encrypt, iv, tag])

        data = sock.recv_multipart()
        decrypt = crypto.symetric_decrypt(shared_key, b'only auth', data[1], data[0], data[2])
        if decrypt == 'LOGOUT SUCCESS':
            print decrypt
            os._exit(0)
        else:
            print 'Error logging out!'


    def error(self, sock, err_msg, shared_key):
        global status
        if status:
            # should be encrypted
            self.logout(sock, shared_key)
        print 'Error: ', err_msg
        os._exit(0)

def main():
    """Gets command line arguments and starts MainHandler
        Main is the function that is run when this file is called.
        It retreives the server-ip, server-port, and username from
        the command line flags.  These arguments are then passed to
        an instance of MainHandler, and the MainHandler instance has
        its' start method called.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-sip", "--server",
                        default="localhost",
                        help="Server IP address or name")

    parser.add_argument("-sp", "--server-port", type=int,
                        default=55005,
                        help="port number of server to connect to")

    parser.add_argument("-u", "--user",
                        default="bob",
                        required=True,
                        help="name of user")

    parser.add_argument("-pr", "--private-key",
                        required=True,
                        help="private key of the client")

    parser.add_argument("-pu", "--public-key",
                        required=True,
                        help="public key of the client")

    parser.add_argument("-pus", "--public-key-server",
                        required=True,
                        help="public key of the server")

    args = parser.parse_args()
    USERNAME = args.user
    PUBLIC_KEY = args.public_key
    PRIVATE_KEY = args.private_key
    with open(PUBLIC_KEY , "rb") as key_file:
        u_public_key = serialization.load_der_public_key(
                key_file.read(),
                backend=default_backend())
    with open(PRIVATE_KEY , "rb") as key_file:
        u_private_key = serialization.load_der_private_key(
                key_file.read(),
                password=None,
                backend=default_backend())
    PUBLIC_KEY_SERVER = args.public_key_server
    with open(PUBLIC_KEY_SERVER , "rb") as key_file:
        s_public_key = serialization.load_der_public_key(
                key_file.read(),
                backend=default_backend())
    PORT = args.server_port
    SERVER_IP = args.server

    t = threading.Thread(target=lestining, args=(u_private_key, u_public_key, USERNAME))
    t.start()

    # lestining()

    mh = MainHandler(SERVER_IP, PORT, USERNAME, s_public_key, u_public_key, u_private_key)
    mh.start()

if __name__ == '__main__':
    main()