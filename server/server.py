#!/usr/bin/env python3

import socket

HOST = ''       # Use default address
PORT = 42424    # Port to listen on (non-privileged ports are > 1023)
Number = -1

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()

    print ("Starting server")

    while True:
        try:
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                Number += 1
                conn.settimeout(1)

                with open("memory" + ("" if Number == 0 else str(Number)) + ".bin", "wb") as file:
                    while True:
                        data = conn.recv(4096)
                        if not data:
                            break

                        file.write(data)
        except socket.timeout:
            print('Connection timed out')