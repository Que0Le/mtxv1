import time, socket, sys

bind_addr = ('10.10.2.22', 4096)
if len(sys.argv)==2:
    bind_addr = (sys.argv[1], 4096)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(bind_addr)

while True:
    message, address = server_socket.recvfrom(1024)
    print(bind_addr, address, message)