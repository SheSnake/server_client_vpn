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

static in_addr addr_v4[5];
void request_ipv4(int fd);
void process_ipv4_assign(Msg* msg);
void process_ipv4_reply(Msg* msg);
void do_keep_alive(Msg* msg, int fd);
void* read_tun_thread(void* argv);

struct tun_config {
    int tun_fd;
    int server_fd;
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
int route_add(char * interface_name)
{
    int skfd;
    struct rtentry rt;

    struct sockaddr_in dst;
    struct sockaddr_in gw;
    struct sockaddr_in genmask;

    memset(&rt, 0, sizeof(rt));

    genmask.sin_family = AF_INET;
    genmask.sin_addr.s_addr = inet_addr("255.0.0.0");

    bzero(&dst,sizeof(struct sockaddr_in));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr("192.0.0.0");

    rt.rt_metric = 2;
    rt.rt_dst = *(struct sockaddr*) &dst;
    rt.rt_genmask = *(struct sockaddr*) &genmask;

    rt.rt_dev = interface_name;
    rt.rt_flags = RTF_UP;// | RTF_HOST ;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(ioctl(skfd, SIOCADDRT, &rt) < 0)
    {
        fprintf(stderr, "Error route add :%d, %s\n",skfd, strerror(errno));
        return -1;
    }
    return 1;
}


int tun_alloc(int flags, char* tun_ip)
{

    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

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

    printf("Open tun/tap device: %s for reading...\n", ifr.ifr_name);

    //激活虚拟网卡增加到虚拟网卡的路由

    char buf[16];
    Inet_ntop(AF_INET, &addr_v4[0], buf,sizeof(buf));
    fprintf(stderr,"tun ip_v4: %s \n",buf);


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
    route_add(ifr.ifr_name);
    return fd;
}


void config_tun()
{

    int tun_fd;
    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *        IFF_NO_PI - Do not provide packet information
     */

   // Inet_pton(AF_INET, "10.0.0.5", &addr_v4[0]);
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
        printf("read %d bytes\n", ret);
        msg.hdr.type = 102;
        msg.hdr.length = ret;
        memcpy((char*)msg.ipv4_payload, buf, ret);
        int ret = Write_nByte(conf->server_fd, (char*) &msg, sizeof(Msg_Hdr) + msg.hdr.length);
//        ret = write(tun, buf, ret);
        printf("write %d bytes\n", ret);
    }
}


void do_client(char* server_ip, char* server_port, char* client_port) {


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
            if(msg.hdr.type != 100 && msg.hdr.type != 104) {
                n = read(sockfd, ipv4_payload, msg.hdr.length);
                if(n != msg.hdr.length) {
                    fprintf(stderr, "read payload error, need %d byte, read %d byte\n",msg.hdr.length, n);
                    if(n <= 0) {
                        Close(sockfd);
                        break;
                    }
                }
                else {
                    if(msg.hdr.type == 102)
                        fprintf(stderr, "read payload ok, need %d byte, read %d byte\n",msg.hdr.length, n);
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
                    fprintf(stderr, "recv an error reqeust %d %d %d\n",msg.hdr.type, msg.hdr.length, n);
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
    for(int i = 0 ; i < 5; ++i) {
        char buf[16];
        Inet_ntop(AF_INET, &(reply->addr_v4[i]), buf,sizeof(buf));
        fprintf(stderr,"recev %d , ip_v4: %s \n",i, buf);
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
        fprintf(stderr,"client write 100 request error, need %d, write %d \n",needbs, n);
    }
    else {
        fprintf(stderr,"send 100 request success\n");
    }
}
void do_keep_alive(Msg* msg, int fd) {
    fprintf(stderr," client read an 104 packet\n");
    memset((char*)msg, 0, sizeof(struct Msg));
    msg->hdr.type = 104;
    msg->hdr.length = 0;
    fprintf(stderr,"------- client send a keep alive to server  ----------\n");
    int n = Write_nByte(fd, (char*)msg, sizeof(struct Msg_Hdr)+msg->hdr.length);
}
void process_ipv4_reply(Msg* msg) {
    ssize_t ret = Write_nByte(conf.tun_fd, (char*)msg->ipv4_payload, msg->hdr.length);
    printf("write %d/%d bytes to tun,\n", ret, msg->hdr.length);
}