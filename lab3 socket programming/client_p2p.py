from io import BufferedIOBase
import sys
import socket
import os
import threading
import errno
client_name = sys.argv[1]
id = sys.argv[2]
total = sys.argv[3]
Port = 2021
BUFFERSIZE=1024
def client():
    HOST = '10.0.0.1'
    ADDR = (HOST, Port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(ADDR)
    print("receive from server")
    with open(client_name+"_tmp.txt", "wb") as f:
        while True:
            data = sock.recv(BUFFERSIZE)
            if not data:
                break
            f.write(data)
    f.close()
    sock.close()


def p2p_server():
    count=0
    sock_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = ("10.0.0.%d" % int (id))
    addr = (host, Port)
    sock_server.bind(addr)
    sock_server.listen(5)
    while True:
        # try to accept a request from clients
        tcpSock, client_address = sock_server.accept()
        count+=1
        print("accept ")
        with open(client_name+"_tmp.txt", "rb") as f:
            while True:
                line = f.readline()
                if not line:
                    break
                sent = tcpSock.send(line)
        f.close()
        tcpSock.close()
        if(count==int(total)):
            break
    sock_server.close()
    os.remove(client_name+"_tmp.txt")
    # if pid > 0:


def p2p_client():
    with open(client_name+".txt", "wb") as f:
        for i in range(2, int(total)+2):
            sock_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            Host = ("10.0.0.%d" % (i))
            print(Host)
            addr = (Host, Port) 
            while(True):
                # try to connect with specific host
                s=sock_client.connect_ex(addr)
                if(s==0):
                    break
            print("connect to %s" % (Host))
            while True:
                data = sock_client.recv(BUFFERSIZE)
                if not data:
                    break
                f.write(data)
            sock_client.close()
    f.close()


if __name__ == "__main__":
    client()
    t1=threading.Thread(target=p2p_server)
    t2=threading.Thread(target=p2p_client)
    t1.start()
    t2.start()
