#include "get_mac_ip.h"
#include <cstdio>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>

Mac get_mac_address(const char *interface) {
    int fd;
    struct ifreq ifr;
    unsigned char *mac;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }

    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    close(fd);

    return Mac(mac);

}

Ip get_ip_address(const char *interface){
    int fd;
    struct ifreq ifr;
    struct sockaddr_in *addr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }

    addr = (struct sockaddr_in *)&ifr.ifr_addr;

    char buf[18];

    if(inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf)) == NULL) {
	    perror("inet_ntop");
	    close(fd);
	    exit(EXIT_FAILURE);
    }

    close(fd);

    return Ip(buf);
}
