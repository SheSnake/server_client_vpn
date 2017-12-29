# SERVER_CLIENT_VPN
An simplify ipv4 proxy

## Feature
- `Safe` aes key exchange through `rsa`  
- `Encrypt` communication data through `aes`    
-  Support `multi client` VPN  
## Require
- `linux os` (only test in ubuntu16.04 you can test in your system)
- `gcc version` 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.5)  
- `libssl-dev`   
- `iptables`  

## Getting Start

### Install&Compile 
Clone this project, your can compile it by our `Makefile` easily.

### Quick Example

#### Configure As A VPN Server 
After compile and install require libs, configure VPN settings by our `configure.sh`, it will change the `nat.sh`, which will be used to configure `iptables` by our tool.  
```
$: ./configure.sh

```
Then you can start your server thorugh such examples:  
```
examples:
1. Start as a VPN server listen 192.168.1.103:9000
$:./main -s -S 192.168.1.103 -P 9000
```

#### Configure As A VPN Client
After compile and install require libs, you can start VPN proxy thorugh such examples:  
```
2. Start as a VPN client connect to server 192.168.1.103:9000 through local port 9002 with route configure routes.txt
$:./main -c -S 192.168.1.103 -P 9000 -p 9002 -R routes.txt
```
Attention, `routes.txt` is a route setting files, it looks as follows:
```
216.58.194.196(ipv4 net)
255.255.255.255(mask)
78.0.0.0
255.0.0.0
172.0.0.0
255.0.0.0
78.16.49.15
255.255.255.255
```
You should set route by ip/mask to specific which route should go through VPN proxy.
