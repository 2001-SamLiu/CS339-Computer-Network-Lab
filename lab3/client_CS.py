import socket
import sys
HOST = '10.0.0.1'
PORT = 2021
BUFFERSIZE = 1024
ADDR = (HOST, PORT)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(ADDR)
# address=input("Enter an address in local")
with open(sys.argv[1]+".txt", "wb") as f:
    while True:
        data = sock.recv(BUFFERSIZE)
        # .decode(encoding='utf-8')
        # decode_data=data.decode(encoding="utf-8")
        f.write(data)
        # f.write("\n")
        if not data:
            break
sock.close()
