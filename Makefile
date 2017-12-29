
OBJS = main.o error_check.o tundemo.o 4over6_server.o 4over6_util.o keep_alive_thread.o crypto.o
HEAD = 4over6_util.h unp.h
main: $(OBJS) $(HEAD)
	g++ -o $@ $(OBJS) -lpthread -lcrypto 

%.o: %.cpp
	g++ -c $< -o $@ -lcrypto -std=c++11

clean: 
	rm main *.o
