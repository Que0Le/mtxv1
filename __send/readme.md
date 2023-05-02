
```bash
make && cpalphabeta.sh
sudo ./xdpsock -i enp2s0 -H 00:07:32:74:c5:3b -G 00:07:32:74:dc:8f -t -T 100000



```


#### Setup share internet
```
ping -6 fe80::7419:23df:2478:806d -I enp1s0
make; sudo ./send_user --filename send_kern.o -d enp7s0 -q

sudo kill -9 "$(pgrep send_user)"

```


```bash
sudo iptables -A FORWARD -o wlp3s0 -i enx00e04c03f3b8 -s 192.168.0.0/24 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -t nat -F POSTROUTING
sudo iptables -t nat -A POSTROUTING -o wlp3s0 -j MASQUERADE
# share internet
# sudo iptables -t nat -A POSTROUTING -o wlp3s0 -j MASQUERADE

# sudo iptables -A FORWARD -i enx00e04c03f3b8 -o wlp3s0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# sudo iptables -A FORWARD -i wlp3s0 -o enx00e04c03f3b8 -j ACCEPT
sudo nano /etc/sysctl.conf
# net.ipv4.ip_forward=1
sudo sysctl -p

### Client
sudo ip route add default via 192.168.1.123
sudo ip route replace default via 192.168.1.123 dev enp1s0 onlink
sudo systemctl restart network-manager.service
```