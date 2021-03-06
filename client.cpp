//
// Created by dalaoshe on 17-10-11.
//

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <linux/if_tun.h>
#include<stdlib.h>
#include<stdio.h>
#include <unistd.h>
#include <cstdio>
#include <errno.h>
#include <net/route.h>
#include "4over6_util.h"
#include "crypto.h"
#include <cstdlib>
#include <string.h>

static in_addr addr_v4[5];
void request_ipv4(int fd);
void negotiate_key(int fd);
void process_ipv4_assign(Msg* msg);
void process_ipv4_reply(Msg* msg);
void do_keep_alive(Msg* msg, int fd);
void* read_tun_thread(void* argv);
static AES_KEY en_key;
static AES_KEY de_key;
static unsigned char userkey[AES_BLOCK_SIZE];
static unsigned char *iv1 = new unsigned char[AES_BLOCK_SIZE];
static unsigned char *iv2 = new unsigned char[AES_BLOCK_SIZE];
	
struct RouteEntry{
    char dst[30];
    char netmask[30];
}routes[1000];

struct tun_config {
    int tun_fd;
    int server_fd;
    uint32_t routes_num;
}conf;
/**
 *  激活接口
 */
int interface_up(char *interface_name)
{
    int s;

    if((s = socket(PF_INET,SOCK_STREAM,0)) < 0)
    {
        printf("Error create socket :%d\n", errno);
        return -1;
    }

    struct ifreq ifr;
    strcpy(ifr.ifr_name, interface_name);

    short flag;
    flag = IFF_UP;
    if(ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
    {
        printf("Error up %s :%d\n",interface_name, errno);
        return -1;
    }

    ifr.ifr_ifru.ifru_flags |= flag;

    if(ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
    {
        printf("Error up %s :%d\n",interface_name, errno);
        return -1;
    }

    return 0;

}

/**
 *  增加到13.8.0.2的路由
 *  同命令:route add -host 13.8.0.2 dev tun0
 */
int route_add(char * interface_name, char* dst_ip, char* dst_netmask)
{
    int skfd;
    struct rtentry rt;

    struct sockaddr_in dst;
    struct sockaddr_in gw;
    struct sockaddr_in genmask;

    memset(&rt, 0, sizeof(rt));

    genmask.sin_family = AF_INET;
    genmask.sin_addr.s_addr = inet_addr(dst_netmask);

    bzero(&dst,sizeof(struct sockaddr_in));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr(dst_ip);

    rt.rt_metric = 2;
    rt.rt_dst = *(struct sockaddr*) &dst;
    rt.rt_genmask = *(struct sockaddr*) &genmask;

    rt.rt_dev = interface_name;
    rt.rt_flags = RTF_UP;// | RTF_HOST ;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(ioctl(skfd, SIOCADDRT, &rt) < 0)
    {
        fprintf(stderr, "Error route add :%d, %s/%s %s\n",skfd,dst_ip, dst_netmask, strerror(errno));
        return -1;
    }
    return 1;
}

uint32_t read_route(char* file, RouteEntry* routes) {
    uint32_t num = 0; char buf[128];
    if(file == NULL) {
        fprintf(stderr, "No Route File\n");
        return num;
    }
    FILE* f = fopen(file, "r");
    if(f == NULL) {
        fprintf(stderr, "Open Route File:%s, Error: %s \n", file,strerror(errno));
    }
    bzero(buf, 128);
    while(fgets(buf, 50, f) != NULL) {
        for(int i = 0; i < 50; ++i)
            if(buf[i] == '\n' || buf[i] == 'r') buf[i] = 0;
        strcpy(routes[num].dst, buf);
        bzero(buf, 128);
        fgets(buf, 50, f);
        for(int i = 0; i < 50; ++i)
            if(buf[i] == '\n' || buf[i] == 'r') buf[i] = 0;
        strcpy(routes[num].netmask, buf);
        bzero(buf, 128);
        num ++;
    }
    return num;
}

void show_route(RouteEntry* routes, int num) {
	fprintf(stderr,"Confirgure follow routes through VPN:\n");
    for(int i = 0; i < num; ++i) {
        fprintf(stderr, "Route IP/MASK: %s/%s\n", routes[i].dst, routes[i].netmask);
    }
	fprintf(stderr,"\n");
}
int tun_alloc(int flags, char* tun_ip)
{

    struct ifreq ifr;
    int fd, err;
    char clonedev[] = "/dev/net/tun";

    if ((fd = open(clonedev, O_RDWR)) < 0) {
        fprintf(stderr," error:%s\n", strerror(errno));
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;
    //strcpy(ifr.ifr_name, clonedev);

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        fprintf(stderr,"%s ioctl error:%s\n",ifr.ifr_name, strerror(errno));
        close(fd);
        return err;
    }

    printf("Step.3 Open tun/tap device: %s for reading...\n\n", ifr.ifr_name);

    //激活虚拟网卡增加到虚拟网卡的路由

    char command[64];
    sprintf(command,"ifconfig %s %s/24",ifr.ifr_name, tun_ip);
    system(command);
    //sprintf(command,"route add -net 13.8.0.0 netmask 255.255.255.0 dev %s",ifr.ifr_name);
    //system(command);
    sprintf(command,"bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'");
    system(command);
//    sprintf(command,"sh iptables.sh");
//    system(command);

    interface_up(ifr.ifr_name);
   // route_add(ifr.ifr_name, NULL, NULL);
    for(uint32_t i = 0 ; i < conf.routes_num; ++i)
        route_add(ifr.ifr_name, routes[i].dst, routes[i].netmask);
    return fd;
}


void config_tun()
{
    int tun_fd;
    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *        IFF_NO_PI - Do not provide packet information
     */
    char tun_ip[16];
    Inet_ntop(AF_INET, &addr_v4[0], tun_ip,sizeof(tun_ip));

    tun_fd = tun_alloc(IFF_TUN | IFF_NO_PI, tun_ip);

    if (tun_fd < 0) {
        perror("Allocating interface");
        exit(1);
    }

    pthread_t tid;
    conf.tun_fd = tun_fd;
    pthread_create(&tid, NULL, &read_tun_thread, &conf);
}

void* read_tun_thread(void* argv) {
    pthread_detach(pthread_self());
    tun_config* conf = (tun_config*)argv;
    ssize_t ret;
    char buf[4096];
	static unsigned char *encrypt_result = new unsigned char[4096];
	static uint8_t *to_encry_data = new uint8_t[4096]; 
	unsigned char *local_iv1 = new unsigned char[AES_BLOCK_SIZE];
    Msg msg;
    bzero(&msg, sizeof(struct Msg));
    bzero(buf, 4096);
    while (1) {
        ret = read(conf->tun_fd, buf, sizeof(buf));
        if (ret < 0)
            break;
//        memcpy(ip, &buf[12], 4);
//        memcpy(&buf[12], &buf[16], 4);
//        memcpy(&buf[16], ip, 4);
//        buf[20] = 0;
//        *((unsigned short*)&buf[22]) += 8;
//        printf("read from tun %ld bytes\n", ret);
	
		//encry
		int32_t len = ret;
		*((int32_t*)to_encry_data) = len;
		memcpy(to_encry_data+sizeof(int32_t), buf, len);
		len += sizeof(int32_t);


//		cout<<"before encry"<<endl;
//		for(int i =0 ; i < len; ++i) {
//			fprintf(stderr,"%u ",*(((uint8_t*)to_encry_data)+i));
//			if(i%8 == 0)cout<<endl;
//		}
//		cout<<endl;

		int32_t encry_len = len;
		int32_t res = (len % AES_BLOCK_SIZE);
		if(len != 0 && res != 0) {
			encry_len += (AES_BLOCK_SIZE-res);
		}
		msg.hdr.type = 102;
		msg.hdr.length = encry_len;
	
		memset((unsigned char*)local_iv1,'m',AES_BLOCK_SIZE);
		memset((unsigned char*)encrypt_result, 0, 4096);
		AES_Encrypt((unsigned char*)to_encry_data, encrypt_result, len, &en_key, local_iv1);
		memcpy((char*)msg.ipv4_payload, encrypt_result, msg.hdr.length);

	//	cout<<"encry result"<<endl;
	//	for(int i =0 ; i < msg.hdr.length; ++i) {
	//		fprintf(stderr,"%u ",*(((uint8_t*)msg.ipv4_payload)+i));
	//		if(i%8 == 0)cout<<endl;
	//	}
	//	cout<<endl;
        
		
		int ret = Write_nByte(conf->server_fd, (char*) &msg, sizeof(Msg_Hdr) + msg.hdr.length);
    }
}


void do_client(char* server_ip, char* server_port, char* client_port, char* route_file) {

    conf.routes_num = read_route(route_file, routes);
    show_route(routes, conf.routes_num);


    struct sockaddr_in server_addr, client_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    memset(&client_addr, 0, sizeof(struct sockaddr_in));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(atoi(server_port));
    Inet_pton(AF_INET, server_ip, &server_addr.sin_addr.s_addr);
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(atoi(client_port));
    socklen_t len = sizeof(struct sockaddr_in6);


    int sockfd = Socket(AF_INET, SOCK_STREAM, 0);
    Bind_Socket(sockfd, (SA*)&client_addr, len);
    Socket_Peer_Connect(sockfd, (SA*)&server_addr, len);
	request_ipv4(sockfd);
    size_t msg_hdr_len = sizeof(struct Msg_Hdr);
    conf.server_fd = sockfd;
    while (1){
        static struct Msg msg;
        memset(&msg, 0, sizeof(struct Msg));
        ssize_t n = read(sockfd, &msg, msg_hdr_len);
        if(n < 0) {
            fprintf(stderr, "read sockfd %d error: %s \n", sockfd,strerror(errno));
            Close(sockfd);
            break;
        }
        else if(n == 0) {
            fprintf(stderr, "close sockfd %d \n",sockfd);
            Close(sockfd);
            break;
        }
        else if(n == msg_hdr_len){
            process_payload:
            uint8_t *ipv4_payload = msg.ipv4_payload;
            if(msg.hdr.type != 100 ) {
                n = read(sockfd, ipv4_payload, msg.hdr.length);
                if(n != msg.hdr.length) {
                    fprintf(stderr, "read payload error, need %d byte, read %ld byte\n",msg.hdr.length, n);
                    if(n <= 0) {
                        Close(sockfd);
                        break;
                    }
                }
                else {
                    if(msg.hdr.type == 102)
                        fprintf(stderr, "read payload ok, need %d byte, read %ld byte\n",msg.hdr.length, n);
                }
                while(n < msg.hdr.length)
                    n += read(sockfd, ipv4_payload+n, msg.hdr.length-n);
            }

            switch(msg.hdr.type){
                case 100: //client ask ipv4 ip
                    break;
                case 101: //client recv ipv4 ip
                    process_ipv4_assign(&msg);
                    config_tun();
					negotiate_key(sockfd);
                    break;
                case 102: //client send ipv4 pkt
                    break;
                case 103: //client recv ipv4 pkt reply
                    process_ipv4_reply(&msg);
                    break;
                case 104:
                    do_keep_alive(&msg, sockfd);
                    break;
                default:
                    fprintf(stderr, "recv an error reqeust %d %d %ld \n",msg.hdr.type, msg.hdr.length, n);
                    break;
            }
        }
        else {// 读到长度小于头长度说明可能出错(也有可能粘包,继续读取)
            while (n < sizeof(struct Msg_Hdr))
                n += read(sockfd, (char*)&msg + n , msg_hdr_len-n);
            fprintf(stderr, "recv an error hdr\n");
            goto process_payload;
        }
    }
}

void process_ipv4_assign(Msg* msg) {
    Ipv4_Request_Reply* reply = (Ipv4_Request_Reply*)msg->ipv4_payload;
    fprintf(stderr,"Step.2 Recev VPN ip assign response(101):\n");
    for(int i = 0 ; i < 5; ++i) {
        char buf[16];
        Inet_ntop(AF_INET, &(reply->addr_v4[i]), buf,sizeof(buf));
		if(i == 0) {
			fprintf(stderr,"Confirgure VPN server assign ip: %s .\n\n",buf);
		}
    }
    for(int i = 0 ; i < 5; ++i)
        addr_v4[i] = reply->addr_v4[i];
}
void request_ipv4(int fd) {
    static struct Msg msg;
    memset(&msg, 0, sizeof(struct Msg));
    size_t needbs = sizeof(struct Msg_Hdr);
    msg.hdr.length = 0;
    msg.hdr.type = 100;

    ssize_t n = Write_nByte(fd, (char*)&msg, needbs);

    if(n < 0) {
        fprintf(stderr,"client write 100 request error: %s\n",strerror(errno));
    }
    if(n != needbs) {
        fprintf(stderr,"client write 100 request error, need %lu, write %lu \n",needbs, n);
    }
    else {
        fprintf(stderr,"Step.1 Send VPN ip assign request(100) success.\n\n");
    }
}

void negotiate_key(int fd) {
    static struct Msg msg;
    memset(&msg, 0, sizeof(struct Msg));
    msg.hdr.length = 128;
    msg.hdr.type = 98;
    
	size_t needbs = sizeof(struct Msg_Hdr) + msg.hdr.length;
	char* aes_key = generatePriKey(8);
	string two = EncodeRSAKeyFile("pubkey.pem", aes_key);  
	char* payload = (char*)msg.ipv4_payload;
	const char* key = two.c_str();
	memcpy(payload, key, 128);

    fprintf(stderr,"Step.4 Generate aes key encrypt through rsa:\n");
    fprintf(stderr,"aes key is:%s\n", aes_key);
	
	
//	cout<<"encry key"<<endl;
//	for(int i =0 ; i < 128; ++i) {
//		fprintf(stderr,"%u ",*(((uint8_t*)msg.ipv4_payload)+i));
//	}
//	cout<<endl;
//	cout<< two.length() <<endl;
//
//	string three = DecodeRSAKeyFile("prikey.pem", two);  
//	cout<<"decry key:"<<three<<endl;	

	memcpy((char*)userkey, aes_key, AES_BLOCK_SIZE);	
	memset((unsigned char*)iv1,'m',AES_BLOCK_SIZE);
	memset((unsigned char*)iv2,'m',AES_BLOCK_SIZE);
	
	AES_set_encrypt_key(userkey, AES_BLOCK_SIZE*8, &en_key);
	AES_set_decrypt_key(userkey, AES_BLOCK_SIZE*8, &de_key);

    ssize_t n = Write_nByte(fd, (char*)&msg, needbs);

    if(n < 0) {
        fprintf(stderr,"client write 98 request error: %s\n",strerror(errno));
    }
    if(n != needbs) {
        fprintf(stderr,"client write 98 request error, need %ld, write %ld \n",needbs, n);
    }
    else {
        fprintf(stderr,"send encry key success.\n\n");
    }
}


void do_keep_alive(Msg* msg, int fd) {
    fprintf(stderr,"client read an 104 packet\n");
	memset((char*)msg, 0, sizeof(struct Msg));
    msg->hdr.type = 104;
	msg->hdr.length = 0;
	fprintf(stderr,"------- client send a keep alive to server  ----------\n");
    int n = Write_nByte(fd, (char*)msg, sizeof(struct Msg_Hdr)+msg->hdr.length);
}
void process_ipv4_reply(Msg* msg) {
	//decrypt
	static unsigned char *decrypt_result = new unsigned char[4096];
	memset((unsigned char*) decrypt_result, 0, msg->hdr.length);
	memset((unsigned char*)iv2,'m',AES_BLOCK_SIZE);
	AES_Decrypt((unsigned char*)(msg->ipv4_payload), decrypt_result,
			msg->hdr.length, &de_key, iv2);
	int32_t len = *((int32_t*)decrypt_result);
	
//	cout<<"recev packet res, len:"<<len<<" "<<(decrypt_result+sizeof(int32_t))<<endl;	
//	
//	cout<<"decrypt packet result"<<endl;
//	for(int i =0 ; i < len; ++i) {
//		fprintf(stderr,"%u ",*(((uint8_t*)decrypt_result)+i));
//		if(i%8 == 0)cout<<endl;
//	}
//	cout<<endl;

    
	ssize_t ret = Write_nByte(conf.tun_fd, (char*)(decrypt_result+sizeof(int32_t)), len);
    
	
//	printf("write %ld/%d bytes to tun,\n", ret, msg->hdr.length);
}
