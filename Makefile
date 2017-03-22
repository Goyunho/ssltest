main=copy.c
include=include
libdir=libs

run: $(main).o
	gcc -o ssl $<

$(main).o: $(main).c
	gcc -c $< -lssl -lcrypto -I$(include) -L$(libdir) -ltest


