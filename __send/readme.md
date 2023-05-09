
```bash
make && cpalphabeta.sh
sudo ./xdpsock -i enp2s0 -H 00:07:32:74:c5:3b -G 00:07:32:74:dc:8f -t -T 100000

sudo ip link set dev enp2s0 xdpdrv off
sudo ip link set dev enp5s0 xdpdrv off
sudo ip link set dev enp7s0 xdpdrv off
sudo ip -force link set dev [DEV] xdpdrv obj xdp.o sec .text

```

## Debug bpf
```bash
bpf_printk("!! pkt_count: %d, index: %d\n", pkt_count, index);
sudo cat /sys/kernel/debug/tracing/trace_pipe
####
# https://manpages.ubuntu.com/manpages/focal/en/man8/bpftool-map.8.html
sudo bpftool map show
# 270: array  name xdp_disp.rodata  flags 0x480
#         key 4B  value 124B  max_entries 1  memlock 4096B
#         btf_id 435  frozen
# 273: percpu_array  name xdp_stats_map  flags 0x0
#         key 4B  value 4B  max_entries 4  memlock 4096B
# 274: xskmap  name xsks_map  flags 0x0
#         key 4B  value 4B  max_entries 4  memlock 4096B
# 275: array  name xdpsock_.rodata  flags 0x480
#         key 4B  value 29B  max_entries 1  memlock 4096B
#         btf_id 438  frozen
sudo bpftool map dump id 273
# key:
# 00 00 00 00
# value (CPU 00): 00 00 00 00
# value (CPU 01): 00 00 00 00
# value (CPU 02): 07 00 00 00
# value (CPU 03): 00 00 00 00
# key:
# 01 00 00 00
# value (CPU 00): 00 00 00 00
# value (CPU 01): 00 00 00 00
# value (CPU 02): 00 00 00 00
# value (CPU 03): 00 00 00 00
# key:
# 02 00 00 00
# value (CPU 00): 00 00 00 00
# value (CPU 01): 00 00 00 00
# value (CPU 02): 55 02 00 00
# value (CPU 03): 00 00 00 00
# key:
# 03 00 00 00
# value (CPU 00): 00 00 00 00
# value (CPU 01): 00 00 00 00
# value (CPU 02): 00 00 00 00
# value (CPU 03): 00 00 00 00
# Found 4 elements
```

#### Setup share internet
```
ping -6 fe80::7419:23df:2478:806d -I enp1s0
make; sudo ./send_user --filename send_kern.o -d enp7s0 -q

sudo kill -9 "$(pgrep send_user)"

```


```bash
# Run after reboot, since iptable will not store these permanently
sudo iptables -A FORWARD -o wlp3s0 -i enx00e04c03f3b8 -s 192.168.0.0/24 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -t nat -F POSTROUTING
sudo iptables -t nat -A POSTROUTING -o wlp3s0 -j MASQUERADE
# share internet
# sudo iptables -t nat -A POSTROUTING -o wlp3s0 -j MASQUERADE

# sudo iptables -A FORWARD -i enx00e04c03f3b8 -o wlp3s0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# sudo iptables -A FORWARD -i wlp3s0 -o enx00e04c03f3b8 -j ACCEPT

# Check sharing status with  cat /proc/sys/net/ipv4/ip_forward
sudo nano /etc/sysctl.conf
# Add this: net.ipv4.ip_forward=1
# Or do this: sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -p

### Client
sudo ip route add default via 192.168.1.123
sudo ip route replace default via 192.168.1.123 dev enp1s0 onlink
sudo systemctl restart network-manager.service
```


```bash
# monitor interfaces.
# This command list status of all queues (rx and tx).
# read [Multi-queue hashing algorithms](https://blog.cloudflare.com/how-to-receive-a-million-packets/)
watch 'sudo ethtool -S enp2s0 | grep rx'
watch 'sudo ethtool -S enp5s0 | grep rx'
# find queue
sudo find /sys/devices/ -name "byte_queue_limits"
# /sys/devices/pci0000:00/0000:00:13.2/0000:03:00.0/0000:04:01.0/0000:05:00.0/net/enp5s0/queues/tx-2/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:13.2/0000:03:00.0/0000:04:01.0/0000:05:00.0/net/enp5s0/queues/tx-0/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:13.2/0000:03:00.0/0000:04:01.0/0000:05:00.0/net/enp5s0/queues/tx-3/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:13.2/0000:03:00.0/0000:04:01.0/0000:05:00.0/net/enp5s0/queues/tx-1/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:13.2/0000:03:00.0/0000:04:03.0/0000:07:00.0/net/enp7s0/queues/tx-2/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:13.2/0000:03:00.0/0000:04:03.0/0000:07:00.0/net/enp7s0/queues/tx-0/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:13.2/0000:03:00.0/0000:04:03.0/0000:07:00.0/net/enp7s0/queues/tx-3/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:13.2/0000:03:00.0/0000:04:03.0/0000:07:00.0/net/enp7s0/queues/tx-1/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:13.0/0000:01:00.0/net/enp1s0/queues/tx-2/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:13.0/0000:01:00.0/net/enp1s0/queues/tx-0/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:13.0/0000:01:00.0/net/enp1s0/queues/tx-3/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:13.0/0000:01:00.0/net/enp1s0/queues/tx-1/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:1e.0/mmc_host/mmc1/mmc1:0001/mmc1:0001:1/net/wlan0/queues/tx-0/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:13.1/0000:02:00.0/net/enp2s0/queues/tx-2/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:13.1/0000:02:00.0/net/enp2s0/queues/tx-0/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:13.1/0000:02:00.0/net/enp2s0/queues/tx-3/byte_queue_limits
# /sys/devices/pci0000:00/0000:00:13.1/0000:02:00.0/net/enp2s0/queues/tx-1/byte_queue_limits
# /sys/devices/virtual/net/lo/queues/tx-0/byte_queue_limits
```