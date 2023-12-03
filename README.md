# ip2domain server

DNS server for convert domain such as `9.9.9.9.ip.recolic.cc` or `1-1-1-1.ip.recolic.cc` to ip address. 

It currently only supports ipv4, but will support ipv6 in the future. 

## Usage

Just run `ip2domain.py` with python3. 

## Note: ubuntu server setup

```
systemctl disable systemd-resolved --now
echo 'nameserver 1.1.1.1' > /etc/resolv.conf
# run this script
```
