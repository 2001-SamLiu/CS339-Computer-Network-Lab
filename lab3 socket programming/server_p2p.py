import sys
import socket
Port = 2021
num = sys.argv[1]

HOST = ""
ADDR = (HOST, Port)


def server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(ADDR)
    sock.listen(5)
    line = 0
    with open("file.txt", "rb") as f:
        while True:
            if(not f.readline()):
                break
            line += 1
    f.close()
    chunk = line/int(num)
    chunk+=1
    count = 0
    server_id = 1
    print(chunk)
    while True:
        tcpSock, addr = sock.accept()
        print("send information ")
        with open("file.txt", "rb") as f:
            while True:
                lines = f.readline()
                if not lines:
                    break
                sent = tcpSock.send(lines)
                count += 1
                if(count == int(chunk)):
                    count = 0
                    # tcpSock.send(b"stop")
                    print("send a chunk")
                    tcpSock.close()
                    tcpSock, addr = sock.accept()
            tcpSock.close()
        break
    sock.close()


if __name__ == '__main__':
    server()
