#include "pk.h"

int read_keyfile(unsigned char* key) {
    FILE* key_file;
    key_file = fopen(PK_FP_KEY, "r");
    if (key_file == NULL) return PK_ERR_NP;
    if (fread(key, sizeof(unsigned char), PK_KEY_BYTES, key_file)
            < PK_KEY_BYTES) {
        fclose(key_file);
        return PK_ERR_INSUF_LEN;
    }
    fclose(key_file);
    return PK_SUCCESS;
}

int read_portfile(unsigned short* ports, int* portc) {
    FILE* port_file;
    char* line = NULL;
    size_t len = 0;
    ssize_t read;
    port_file = fopen(PK_FP_PORTS, "r");
    if (port_file == NULL) return PK_ERR_NP;
    while ((read = getline(&line, &len, port_file)) != -1) {
        if (*portc == PK_MAX_PORTC) return PK_ERR_EXTRA_LEN;
        ports[(*portc)++] = atoi(line);
    }
    return PK_SUCCESS;
}

int get_netconfig(int sfd, char* iface, int* mtu, in_addr_t* s_addr) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sfd, SIOCGIFMTU, &ifr) == -1) return PK_ERR_IFR_MTU;
    *mtu = ifr.ifr_mtu;
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(sfd, SIOCGIFADDR, &ifr) == -1) return PK_ERR_IFR_ADDR;
    struct sockaddr_in* sin;
    sin = (struct sockaddr_in*) &ifr.ifr_addr;
    *s_addr = sin->sin_addr.s_addr;
    return PK_SUCCESS;
}
