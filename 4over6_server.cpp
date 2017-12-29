//
// Created by dalaoshe on 17-4-13.
//
#include "4over6_util.h"
#include "crypto.h"
#define MAX_BACKLOG 20
static struct User_Tables user_tables;


int negotiate_to_client_ipv4(int fd, struct Msg* c_msg);
int do_response(int fd, int rawfd, int i, struct sockaddr_in *client_addr, socklen_t *len);
void reply_ipv4_request(int fd, sockaddr_in* client_addr, socklen_t* clientlen);
void do_ipv4_packet_request(int fd, int rawfd, struct Msg* msg);
void do_keep_alive(int fd);

static struct sockaddr_in server_addr, client_addr;
static int i, maxi, maxfd, connfd, sockfd, raw_udp_fd, raw_tcp_fd, raw_out_fd;
static int nready, client[FD_SETSIZE];
static fd_set rset, allset;
pthread_mutex_t allset_mutex;

void process_packet(char* buffer , uint32_t size)
{
    static struct Msg msg;
    struct iphdr *iph = (struct iphdr*)buffer;
    User_Info* info = user_tables.get_user_info_by_v4(iph->daddr);
    char buf[16],buf2[16];
    Inet_ntop(AF_INET, &iph->daddr, buf,sizeof(buf));
    Inet_ntop(AF_INET, &iph->saddr, buf2,sizeof(buf2));
    if(iph->protocol == IPPROTO_TCP && info != NULL && info->state != FREE)
        fprintf(stderr,"Recev TCP PKT From IP: %s Should Sent To IP: %s \n",buf2, buf);
    else if(iph->protocol == IPPROTO_UDP && info != NULL && info->state != FREE)
        fprintf(stderr,"Recev UDP PKT From IP: %s Should Sent To IP: %s \n",buf2, buf);
    else if(iph->protocol == IPPROTO_ICMP && info != NULL && info->state != FREE)
        fprintf(stderr,"Recev ICMP PKT From IP: %s Should Sent To IP: %s \n",buf2, buf);
    else if(iph->protocol == IPPROTO_ICMPV6 && info != NULL && info->state != FREE)
        fprintf(stderr,"Recev ICMPv6 PKT From IP: %s Should Sent To IP: %s \n",buf2, buf);

    if(info == NULL || info->state == FREE)return;
    fprintf(stderr," ---- Recev A Valid PKT From IP: %s Should Sent To IP: %s   ---- \n",buf2, buf);



    memset(&msg, 0, sizeof(struct Msg));



	static unsigned char *encrypt_result = new unsigned char[4096];
	static uint8_t *to_encry_data = new uint8_t[4096]; 
	
	int32_t len = size;
	*((int32_t*)to_encry_data) = len;
	memcpy(to_encry_data+sizeof(int32_t), buffer, len);
	len += sizeof(int32_t);

	cout<<"before encry"<<endl;
	for(int i =0 ; i < len; ++i) {
		fprintf(stderr,"%u ",*(((uint8_t*)to_encry_data)+i));
			if(i%8 == 0)cout<<endl;
	}
	cout<<endl;

	int32_t encry_len = len;
	int32_t res = (len % AES_BLOCK_SIZE);
	if(len != 0 && res != 0) {
		encry_len += (AES_BLOCK_SIZE-res);
	}
	msg.hdr.type = 103;
	msg.hdr.length = encry_len;
	
	memset((unsigned char*)info->iv1,'m',AES_BLOCK_SIZE);
	memset((unsigned char*)encrypt_result, 0, 4096);
	AES_Encrypt((unsigned char*)to_encry_data, encrypt_result, len, &info->en_key, info->iv1);
	memcpy((char*)msg.ipv4_payload, encrypt_result, msg.hdr.length);

	cout<<"encry result"<<endl;
	for(int i =0 ; i < msg.hdr.length; ++i) {
		fprintf(stderr,"%u ",*(((uint8_t*)msg.ipv4_payload)+i));
		if(i%8 == 0)cout<<endl;
	}
	cout<<endl;



    int fd = info->fd;
    if(fd != -1)
        Write_nByte(fd, (char*)&msg, sizeof(struct Msg_Hdr) + msg.hdr.length);

}

void do_server(char* server_ip, char* server_port) {


    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(atoi(server_port));
    Inet_pton(AF_INET, server_ip, &server_addr.sin_addr.s_addr);
    socklen_t client_addr_len = sizeof(struct sockaddr_in);


    int listenfd = Socket(AF_INET, SOCK_STREAM, 0);


    int on = 1;
    SetSocket(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    Bind_Socket(listenfd, (SA*)&server_addr, sizeof(struct sockaddr_in));
    Listen(listenfd, MAX_BACKLOG);

    int raw_tcp_fd = Socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int raw_icmp_fd = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int raw_icmpv6_fd = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMPV6);
    int raw_udp_fd = Socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    int raw_out_fd = Socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    SetSocket(raw_udp_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    SetSocket(raw_tcp_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    SetSocket(raw_icmp_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    SetSocket(raw_icmpv6_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    SetSocket(raw_out_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    struct sockaddr addr;
    char buf[65536];
    int datasize;
    socklen_t saddr_size =  sizeof(addr);
    maxfd = raw_udp_fd;
    maxi = -1;

    for(i = 0; i < FD_SETSIZE; ++i) client[i] = -1;
    FD_ZERO(&allset);
    FD_SET(listenfd, &allset);
    FD_SET(raw_tcp_fd, &allset);
    FD_SET(raw_udp_fd, &allset);
    FD_SET(raw_icmp_fd, &allset);
    FD_SET(raw_icmpv6_fd, &allset);

    in_addr star;
    in_addr end;
    Inet_pton(AF_INET,"10.0.0.3",&star);
    Inet_pton(AF_INET,"10.0.0.10",&end);
    user_tables.init_ipv4_pool(star, end);

    keep_alive_thread_argv argv;
    argv.allset = &allset;
    argv.client = client;
    argv.table = &user_tables;
    pthread_t keep_alive;
    pthread_create(&keep_alive, NULL, &keep_alive_thread, (void*)&argv);


    while (1) {
        rset = allset;
        nready = Select(maxfd+1, &rset, NULL, NULL, NULL);
        if(FD_ISSET(listenfd, &rset)) {// 接收一个新的连接
            connfd = Accept(listenfd, (SA*)&client_addr, &client_addr_len);
            char ip[16];
            Inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
            fprintf(stderr, "A Client From IP:%s, Port %d, Socket %d\n",ip,client_addr.sin_port,connfd);
            for(i = 0; i < FD_SETSIZE; ++i) {
                if(client[i] == -1) {
                    client[i] = connfd;
                    break;
                }
            }
            if(i == FD_SETSIZE) {
                fprintf(stderr, "Too Many Client Connected !\n");
            }

            set_FD_SET(&allset, connfd, &allset_mutex);

            if(connfd > maxfd) maxfd = connfd;
            if(i > maxi) maxi = i;
            if(--nready <= 0)continue;
        }

        if(FD_ISSET(raw_tcp_fd, &rset)) {
            memset(buf, 0, sizeof(buf));
            datasize = recvfrom(raw_tcp_fd, buf, 65536, 0, &addr, &saddr_size );
            process_packet(buf, datasize);
        }
        if(FD_ISSET(raw_udp_fd, &rset)) {
            memset(buf, 0, sizeof(buf));
            datasize = recvfrom(raw_udp_fd, buf, 65536, 0, &addr, &saddr_size );
            process_packet(buf, datasize);
        }
        if(FD_ISSET(raw_icmp_fd, &rset)) {
            memset(buf, 0, sizeof(buf));
            datasize = recvfrom(raw_icmp_fd, buf, 65536, 0, &addr, &saddr_size );
            process_packet(buf, datasize);
        }
        if(FD_ISSET(raw_icmpv6_fd, &rset)) {
            memset(buf, 0, sizeof(buf));
            datasize = recvfrom(raw_icmpv6_fd, buf, 65536, 0, &addr, &saddr_size );
            process_packet(buf, datasize);
        }

        for(i = 0 ; i <= maxi; ++i) {
            if((sockfd = client[i]) < 0) {
                continue;
            }
            if(FD_ISSET(sockfd, &rset)) { // 该socket有客户请求到达
                memset(&client_addr, 0, sizeof(client_addr));
                socklen_t  len = sizeof(client_addr);
                Getpeername(sockfd, (SA*)&client_addr, &len);
                char ipv4[16];
                Inet_ntop(AF_INET, &client_addr.sin_addr, ipv4, sizeof(ipv4));
                fprintf(stderr, "Recv A Packet Transmission Request From IP:%s, Port %d, Socket %d\n",ipv4,client_addr.sin_port,sockfd);
                int result = do_response(sockfd, raw_out_fd, i, &client_addr, &len);

                if(result < 0) {//
                    clr_FD_SET(&allset, sockfd, &allset_mutex);
                    client[i] = -1;
                    fprintf(stderr, "Closing Client Connection From IP:%s, Port %d, Socket %d\n",ipv4,client_addr.sin_port,sockfd);
                    user_tables.free_resource_of_fd(sockfd);
                    fprintf(stderr, "Close Ok\n");
                }
                if(--nready <= 0)break;
            }
        }
    }
}

int do_response(int fd, int rawfd, int i, struct sockaddr_in *client_addr, socklen_t *len) {
    ssize_t n;
    static struct Msg msg;
    memset(&msg, 0, sizeof(struct Msg));
    ssize_t needbs = sizeof(struct Msg_Hdr);

    n = read(fd, (char*)&msg, sizeof(struct Msg_Hdr));
    if(n < 0) {
        fprintf(stderr, "Read Sockfd %d Error: %s \n",fd,strerror(errno));
        Close(fd);
        return -1;
    }
    else if(n == 0) {
        fprintf(stderr, "Close Sockfd %d \n",fd);
        Close(fd);
        return -1;
    }
    else if(n == needbs){
        process_payload:
        uint8_t * ipv4_payload = msg.ipv4_payload;
//        fprintf(stderr, "%d read request type:%d\n",n, msg.hdr.type);
//        for(int i = 0 ; i < n; ++i) {
//            fprintf(stderr, "%02X ", ((char*)&msg)[i]);
//        }
//        fprintf(stderr, "\n");
        if(msg.hdr.type != 100 ) {
            n = read(fd, ipv4_payload, msg.hdr.length);
            if(n != msg.hdr.length) {
                if(n <= 0) {
                    fprintf(stderr, "Read Payload Error, Need %d byte, Read %ld Byte\n",msg.hdr.length, n);
                    Close(fd);
                    return -1;
                }
            }
            else {
                if(msg.hdr.type == 102)
                    fprintf(stderr, "Read Payload ok, Need %d byte, Read %ld Byte\n",msg.hdr.length, n);
            }
            while(n < msg.hdr.length) {
                fprintf(stderr, "Payload Is Divided, Need %d byte, Read %ld Byte\n",msg.hdr.length, n);
                n += read(fd, ipv4_payload + n, msg.hdr.length - n);
            }
        }

        switch(msg.hdr.type){
			case 98:
                fprintf(stderr, "Recv A 98 Request\n");
				negotiate_to_client_ipv4(fd, &msg);
				break;
			case 99:
                fprintf(stderr, "Recv A 99 Request\n");
				break;
            case 100:
                fprintf(stderr, "Recv A 100 Request\n");
                reply_ipv4_request(fd, client_addr, len);
                fprintf(stderr, "Reply A 100 Request Over\n");
                break;
            case 101:
                break;
            case 102: {
                fprintf(stderr, "Recv A 102 Request, PKT_LEN=%d, Read n=%ld\n", msg.hdr.length, n);

//                char *buf = (char *) msg.ipv4_payload;
//                char ip[4];
//                memcpy(ip, &buf[12], 4);
//                memcpy(&buf[12], &buf[16], 4);
//                memcpy(&buf[16], ip, 4);
//                buf[20] = 0;
//                *((unsigned short *) &buf[22]) += 8;
//                printf("read %d bytes\n", msg.hdr.length);
//                msg.hdr.type = 103;
//                int ret = Write_nByte(fd, (char *) &msg, sizeof(Msg_Hdr) + msg.hdr.length);
//                printf("write %d bytes\n", ret);

                do_ipv4_packet_request(fd, rawfd, &msg);
                break;
            }
            case 103: {
                break;
            }
            case 104: {
				cout<<"recv an 104"<<endl;
				for(int i =0 ; i < msg.hdr.length; ++i) {
					fprintf(stderr,"%u ",*(((uint8_t*)msg.ipv4_payload)+i));
				}
				cout<<endl;


				User_Info* info = user_tables.get_user_info_by_fd(fd);
				static unsigned char *decrypt_result = new unsigned char[4096];
				memset((unsigned char*)decrypt_result, 0, msg.hdr.length);
				memset((unsigned char*)info->iv2,'m',AES_BLOCK_SIZE);
				AES_Decrypt((unsigned char*)(msg.ipv4_payload), decrypt_result,msg.hdr.length, &info->de_key, info->iv2);
				int32_t len = *((int32_t*)decrypt_result);
				
				cout<<"len:"<<len<<" "<<(decrypt_result+sizeof(int32_t))<<endl;	
                
				fprintf(stderr,"Recv A 104 Live PKT_LEN=%d %ld\n",msg.hdr.length, n);
                do_keep_alive(fd);
                break;
			}
            default:
                fprintf(stderr, "Recv A Error Reqeust %d %d %ld\n",msg.hdr.type, msg.hdr.length, n);
                break;
        }
    }
    else {// 读到长度小于头长度说明可能出错(也有可能粘包,继续读取)
        fprintf(stderr, "Read %ld byte, Recv an error hdr\n", n);
        while (n < sizeof(struct Msg_Hdr))
            n += read(fd, (char*)&msg + n , sizeof(struct Msg_Hdr)-n);
        fprintf(stderr, "Recv an error hdr\n");
        goto process_payload;
    }
    return 0;
}

void reply_ipv4_request(int fd, sockaddr_in* client_addr, socklen_t* clientlen) {
    static struct Msg msg;
    memset(&msg, 0, sizeof(struct Msg));
    User_Info* info = user_tables.get_free_v4_addr();
    if(info == NULL) {
        return;
    }
    fprintf(stderr,"set user info\n");
    //设置连接信息
    info->setUserInfo(fd,client_addr->sin_addr);
    fprintf(stderr,"set user info over\n");
    user_tables.set_fd_info_map(fd,info);
    fprintf(stderr,"set user table info over\n");
    msg.hdr.type = 101;
    Ipv4_Request_Reply *payload = (Ipv4_Request_Reply*)msg.ipv4_payload;
    payload->addr_v4[0] = info->addr_v4;
    Inet_pton(AF_INET,"0.0.0.0",&(payload->addr_v4[1])); // 注意得到的字节序
    Inet_pton(AF_INET,"8.8.8.8",&(payload->addr_v4[2]));
    Inet_pton(AF_INET,"202.38.120.242",&(payload->addr_v4[3]));
    Inet_pton(AF_INET,"202.106.0.20",&(payload->addr_v4[4]));
    msg.hdr.length = sizeof(struct Ipv4_Request_Reply);

    info->mutex_write_FD((char*)&msg, sizeof(struct Msg_Hdr)+msg.hdr.length);
//    ssize_t n = write(fd, &msg, sizeof(struct Msg_Hdr)+msg.hdr.length);
//
//    if(n != sizeof(struct Msg_Hdr)+msg.hdr.length) {
//        fprintf(stderr, "write reply error, need %d byte, write %d byte\n",sizeof(struct Msg_Hdr)+msg.hdr.length, n);
//        if(n <= 0)
//            return;
//    }
}

void do_ipv4_packet_request(int fd, int rawfd, struct Msg* c_msg) {
    User_Info* info = user_tables.get_user_info_by_fd(fd);
    if(info == NULL) {
        return;
    }
    info->setLatestTime();
	
	cout<<"recv encry result"<<endl;
	for(int i =0 ; i < c_msg->hdr.length; ++i) {
		fprintf(stderr,"%u ",*(((uint8_t*)c_msg->ipv4_payload)+i));
		if(i%8 == 0)cout<<endl;
	}
	cout<<endl;
	//decrypt
	static unsigned char *decrypt_result = new unsigned char[4096];
	memset((unsigned char*)decrypt_result, 0, c_msg->hdr.length);
	memset((unsigned char*)info->iv2,'m',AES_BLOCK_SIZE);
	AES_Decrypt((unsigned char*)(c_msg->ipv4_payload), decrypt_result,
			c_msg->hdr.length, &info->de_key, info->iv2);
	int32_t len = *((int32_t*)decrypt_result);
	cout<<"len:"<<len<<" "<<(decrypt_result+sizeof(int32_t))<<endl;	
    
	cout<<"decrypt result"<<endl;
	for(int i =0 ; i < len; ++i) {
		fprintf(stderr,"%u ",*(((uint8_t*)decrypt_result)+i));
		if(i%8 == 0)cout<<endl;
	}
	cout<<endl;

    //获取目的地址
    iphdr* ipv4hdr = (iphdr*)(decrypt_result+sizeof(int32_t));
    struct sockaddr_in dstaddr,srcaddr;
    dstaddr.sin_addr.s_addr = ipv4hdr->daddr;
    dstaddr.sin_family = AF_INET;
    socklen_t addr_len = sizeof(struct sockaddr_in);

    srcaddr.sin_addr.s_addr = ipv4hdr->saddr;
    srcaddr.sin_family = AF_INET;


    char buf[512],buf2[512];
    Inet_ntop(AF_INET,&(srcaddr.sin_addr.s_addr), buf, sizeof(buf));
    Inet_ntop(AF_INET,&(dstaddr.sin_addr.s_addr), buf2, sizeof(buf2));
    fprintf(stderr,"\n\nRecv an ipv4 request(102) from %s to %s \n\n",buf , buf2);
//    for(int i = 0 ; i < c_msg->hdr.length; ++i) {
//        uint32_t temp = 0;
//        temp = c_msg->ipv4_payload[i];
//        fprintf(stderr,"%02x i:%d ",(temp),i);
//    }
//    fprintf(stderr,"\n\n");
    
	
	ssize_t n = sendto(rawfd, decrypt_result+sizeof(int32_t), len, 0, (SA*)&dstaddr, addr_len);

    if(n != len) {
        fprintf(stderr, "write reply error, need %d byte, write %ld byte\n",len, n);
        if(n <= 0)
            return;
    }
}

#include <iostream>
using namespace std;
int negotiate_to_client_ipv4(int fd, struct Msg* c_msg) {
	cout<<"Recv encry key"<<endl;	
	for(int i =0 ; i < 128; ++i) {
		fprintf(stderr,"%u ",*(((uint8_t*)c_msg->ipv4_payload)+i));
	}
	cout<<endl;

	string two = string(128, 0);
	for(int i = 0; i < 128; ++i) {
		two[i] = c_msg->ipv4_payload[i];
	}
	cout<<two.length()<<endl;

	string three = DecodeRSAKeyFile("prikey.pem", two);  
	cout << "private decrypt key: " << three << endl;
   
	

	User_Info* info = user_tables.get_user_info_by_fd(fd);
	if(info == NULL) {
		cout << "error" << endl;
	}
	else {
		info->key = three;	
		cout << "private decrypt: " << info->key << endl;
		memset((unsigned char*)info->iv1,'m',AES_BLOCK_SIZE);
		memset((unsigned char*)info->iv2,'m',AES_BLOCK_SIZE);
		unsigned char* userkey = (unsigned char*)(info->key.c_str());
		AES_set_encrypt_key(userkey, AES_BLOCK_SIZE*8, &info->en_key);
		AES_set_decrypt_key(userkey, AES_BLOCK_SIZE*8, &info->de_key);
	}	

}

void do_keep_alive(int fd) {
    static struct Msg msg;
    memset(&msg, 0, sizeof(struct Msg));
    User_Info* info = user_tables.get_user_info_by_fd(fd);
    if(info == NULL) {
        return;
    }
    info->setLatestTime();
    return;
}
