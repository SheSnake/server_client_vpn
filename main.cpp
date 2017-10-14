#include "4over6_util.h"

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

}
void initconfig() {
    config.client_port = config.server_port = config.server_ip = config.key = NULL;
    config.route_file = NULL;
    config.type = 0;
}
void showConf(Config* conf) {
    fprintf(stderr, "SERVER IP:%s \n"
            "SERVER PORT:%s\n"
            "LOCAL PORT:%s\n"
            "KEY:%s\n"
            "TYPE:%c\n", conf->server_ip, conf->server_port, conf->client_port, conf->key, conf->type);
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


