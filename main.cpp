#include "4over6_util.h"
#include "test_server_nat.h"

 int main(int argc, char** argv) {
    if(strcmp(argv[1],"1") == 0) {
        do_server(argv[2], argv[3]);
    }
    else {
        do_client(argv[2], argv[3], argv[4]);
    }
    return 0;
}


