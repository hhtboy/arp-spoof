LDLIBS=-lpcap

all: send-arp


main.o: get_mac_ip.h mac.h ip.h ethhdr.h arphdr.h iphdr.h main.cpp 

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

get_mac_ip.o : get_mac_ip.h get_mac_ip.cpp

send-arp: main.o arphdr.o ethhdr.o ip.o mac.o get_mac_ip.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp *.o
