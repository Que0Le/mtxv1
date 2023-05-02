import time, socket, sys

send_sleep_ms = 1000
remote_addr = ("192.168.122.99", 4096)
if len(sys.argv) >= 3:
    remote_addr = (sys.argv[1], int(sys.argv[2]))
print(f"remote_addr: {str(remote_addr)}")
if len(sys.argv) == 4:
    send_sleep_ms = int(sys.argv[3])


send_th = 0
while True:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.connect(('8.8.8.8', 1))  # connect() for UDP doesn't send packets
    local_ip_address = client_socket.getsockname()[0]
    message = f'[{str(send_th)}] [{time.time()}] msg from {local_ip_address} to remote_addr: {str(remote_addr)}'
    client_socket.sendto(message.encode(), remote_addr)
    print(f"__ sent [{str(send_th)}]")
    send_th += 1
    time.sleep(send_sleep_ms/1000)