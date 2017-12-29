#include "4over6_util.h"
#include "crypto.h"
//
// Created by dalaoshe on 17-4-16.
//
void sendKeepAlive(User_Info* info) {
    static struct Msg msg;
    memset(&msg, 0, sizeof(struct Msg));
    msg.hdr.type = 104;
    msg.hdr.length = 0;
	
	char buf[] = "11112222333344445";
	int len = strlen(buf);
	int encry_len = len;
	int res = (len % AES_BLOCK_SIZE);
	if(len != 0 && res != 0) {
		encry_len += (AES_BLOCK_SIZE-res);
	}
    msg.hdr.length = encry_len;
	static unsigned char *encrypt_result = new unsigned char[4096];
	memset((unsigned char*)info->iv1,'m',AES_BLOCK_SIZE);
	memset((unsigned char*)encrypt_result, 0, 4096);
	AES_Encrypt((unsigned char*)buf, encrypt_result, len, &info->en_key, info->iv1);
	memcpy((char*)msg.ipv4_payload, encrypt_result, msg.hdr.length);
	for(int i =0 ; i < msg.hdr.length; ++i) {
		fprintf(stderr,"%u ",*(((uint8_t*)msg.ipv4_payload)+i));
	}
	cout<<endl;
	
	
	fprintf(stderr,"------- keep_alive_thread send a keep alive to fd %d ----------\n",info->fd);
//    ssize_t n = write(fd, &msg, sizeof(struct Msg_Hdr)+msg.hdr.length);
    info->mutex_write_FD((char*)&msg, sizeof(struct Msg_Hdr)+msg.hdr.length);
//    Write_nByte(fd, (char*)&msg, sizeof(struct Msg_Hdr)+msg.hdr.length);
}
void* keep_alive_thread(void* argv) {
    pthread_detach(pthread_self());
    fprintf(stderr,"--------- keep_alive_thread start ----------\n");

    keep_alive_thread_argv* arg = (keep_alive_thread_argv*)argv;
    User_Tables* table = arg->table;
    fd_set* allset = arg->allset;
    int* client = arg->client;

    while(true) {
        sleep(1);
        map<in_addr_t , User_Info*>::iterator it = table->v4_map_info.begin();
        for (it; it != table->v4_map_info.end(); ++it) {

            User_Info *info = it->second;
            if(info->state == FREE) continue;

            info->decCount();
            bool needSendKeep = info->needSendKeepAlive();
            if(needSendKeep) {
                sendKeepAlive(info);
                info->resetCount();
            }
            bool timeout = info->isTimeOut();
            if(timeout) {
                int fd = info->fd;
                if(fd != -1) {
                    fprintf(stderr,"--------- keep_alive_thread close fd %d because of timeout ---------\n",fd);
                    table->free_resource_of_fd(fd);
                    clr_FD_SET(allset, fd, &allset_mutex);
                    for(int i = 0 ; i < FD_SETSIZE; ++i) {
                        if(client[i] == fd) {
                            client[i] = -1;
                            break;
                        }
                    }
                    fprintf(stderr,"--close fd--\n");
                    Close(fd);
                    fprintf(stderr,"--------- keep_alive_thread close fd %d because of timeout ok ---------\n",fd);
                }
            }
        }
    }
    return NULL;
}
