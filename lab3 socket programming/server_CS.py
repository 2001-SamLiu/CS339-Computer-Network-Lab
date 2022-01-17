import socket
from time import *
import threading


def run(socket):
    with open("file.txt", "rb") as f:
        while True:
            line = f.readline()
            sent = socket.send(line)
            if not line:
                break
    tcpSock.close()


BUFFERSIZE = 1024
PORT = 2021
HOST = ''
ADDR = (HOST, PORT)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(ADDR)
sock.listen(5)
data = []
# while True:
#     print("server start\n")
#     tcpSock,addr=sock.accept()
#     begin_time=time()
#     with open("/home/samliu/socket_programming/file.txt","rb") as f:
#         while True:
#             line=f.readline()
#             sent=tcpSock.send(line)
#             if not line:
#                 break
#     end_time=time()
#     run_time=end_time-begin_time
#     print("运行时间为：",run_time)
#     tcpSock.close()
# sock.close()
if __name__ == '__main__':
    while True:
        print("server start\n")
        tcpSock, addr = sock.accept()
        thread = threading.Thread(target=run,args=(tcpSock,))
        thread.start()
        # thread.join()
    sock.close()
