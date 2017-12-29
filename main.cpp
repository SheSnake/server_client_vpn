#include "4over6_util.h"
#include<iostream>
using namespace std;
#define ARGS "hscS:P:p:k:R:"

struct Config{
    char* server_ip;
    char* server_port;
    char* client_port;
    char* key;
    char* route_file;
    char type;
}config;
void usage() {
	cout<<"This is a Ipv4 VPN tool"<<endl;	
	cout<<"Usage Command Options:"<<endl;
	cout<<"-s	start as a VPN server\n"
		<<"-c	start as a VPN client\n"
		<<"-S	VPN server ip\n"
		<<"-P	VPN server port\n"
		<<"-p	VPN client port\n"
		<<"-R	client config file(used to configure route through VPN, format see README)\n"<<endl;
	cout<<"examples:\n"
		<<"1. Start as a VPN server listen 192.168.1.103:9000\n"
		<<"./main -s -S 192.168.1.103 -P 9000\n"
		<<"2. Start as a VPN client connect to server 192.168.1.103:9000 through local port 9002 with route configure routes.txt\n"
		<<"./main -c -S 192.168.1.103 -P 9000 -p 9002 -R routes.txt\n"<<endl;
}
void initconfig() {
    config.client_port = config.server_port = config.server_ip = config.key = NULL;
    config.route_file = NULL;
    config.type = 0;
}
void showConf(Config* conf) {
	if(conf->type == 'c') {
		cout<<"VPN start as client by follow settings:"<<endl;
		cout<<"-S	VPN SERVER IP:"<<conf->server_ip<<endl;
		cout<<"-P	VPN SERVER PORT:"<<conf->server_port<<endl;
		cout<<"-p	VPN CLIENT BIND PORT:"<<conf->client_port<<endl;
		cout<<"-R	VPN CLIENT ROUTE CONFIGURE FILE:"<<conf->route_file<<endl;
	}
	else if(conf->type == 's') {
		cout<<"VPN start as Server by follow settings:"<<endl;
		cout<<"-S	VPN SERVER LISTEN IP:"<<conf->server_ip<<endl;
		cout<<"-P	VPN SERVER LISTEN PORT:"<<conf->server_port<<endl;
	}
	cout<<endl;
}
 int main(int argc, char** argv) {
    char ch = 0;
    while( (ch = getopt(argc, argv, ARGS)) != -1)
        switch (ch) {
            case 'S':
                config.server_ip = optarg;
                break;
            case 'P':
                config.server_port = optarg;
                break;
            case 'p':
                config.client_port = optarg;
                break;
            case 'k':
                config.key = optarg;
                break;
            case 's':
                config.type = 's';
                break;
            case 'c':
                config.type = 'c';
                break;
            case 'R':
                config.route_file = optarg;
                break;
            case 'h':
                usage();
                exit(0);
            default:
                break;
        }
    showConf(&config);

    switch (config.type) {
        case 's':
            do_server(config.server_ip, config.server_port);
            break;
        case 'c':
            do_client(config.server_ip, config.server_port, config.client_port, config.route_file);
            break;
        default:
            usage();
            break;
    }

    return 0;
}


