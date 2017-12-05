#!/usr/bin/python

import argparse
import socket
import pickle
import threading
import sys
from random import randint
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends.interfaces import DHBackend
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
print_lock = threading.Lock()

def handler(conn):
    while True:
        data = conn.recv(2048)
        parameters = load_pem_parameters(data, backend=default_backend())
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        conn.send(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        data = conn.recv(2048)
        peer_public_key = load_pem_public_key(data, backend=default_backend())
        shared_key = private_key.exchange(peer_public_key)
        print shared_key
        print_lock.release()
        return

if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', 55005))
    sock.listen(1)
    while True: 
        c, addr = sock.accept()
        print('Connected')
        print_lock.acquire()
        t = threading.Thread(target=handler, args=(c,))
        t.start()
    main()
