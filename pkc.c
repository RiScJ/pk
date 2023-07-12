#include "pk.h"
#include "pkc.h"

int encrypt(unsigned char* ptext, int ptext_len, unsigned char* key,
        unsigned char* iv, unsigned char* ctext) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int ctext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        return -1;
    }
    if (1 != EVP_EncryptUpdate(ctx, ctext, &len, ptext, ptext_len)) {
        return -1;
    }
    ctext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ctext + len, &len)) return -1;
    ctext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ctext_len;
}

int gen_iv(unsigned char* iv) {
    return RAND_bytes(iv, PK_IV_BYTES);
}

int parse_arguments(int argc, char** argv, char* iface, char* fqdn) {
    if (argc < PKC_ARGC) return PK_ERR_INSUF_LEN;
    if (argc > PKC_ARGC) return PK_ERR_EXTRA_LEN;
    if (strlen(argv[PKC_ARGN_IFACE]) > PK_IFACE_MAX_LEN 
            || strlen(argv[PKC_ARGN_FQDN]) > PK_FQDN_MAX_LEN)
                    return PK_ERR_BUF_OF; 
    
    strcpy(iface, argv[PKC_ARGN_IFACE]);
    strcpy(fqdn, argv[PKC_ARGN_FQDN]);
    return 0;
}

int resolve_fqdn(char* fqdn, in_addr_t* daddr) {
    struct hostent* h;
    h = gethostbyname(fqdn);
    if (h == NULL) return PK_ERR_NP;
    struct in_addr* target;
    target = (struct in_addr*) (h->h_addr);
    *daddr = target->s_addr;
    return 0;
}

int init_socket(int* sockfd) {
    *sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (*sockfd == -1) return PK_ERR_SOCK_NEW;
    int one = 1;
    const int* one_a = &one;
    if (setsockopt(*sockfd, IPPROTO_IP, IP_HDRINCL, one_a, 
            sizeof(one)) < 0) {
        close(*sockfd);
        return PK_ERR_SOCK_OPT;
    }
    return 0;
}

int get_netconfig(int sfd, char* iface, int* mtu, 
        in_addr_t* s_addr) {
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
    return 0;
}

int init_datagram(in_addr_t saddr, in_addr_t daddr, int mtu, char* dgram, 
        struct iphdr* iph, struct tcphdr* tcph) { 
    iph = (struct iphdr*) dgram;
    tcph = (struct tcphdr*) (dgram + sizeof(struct iphdr));
    memset(dgram, 0, mtu);
    
    tcph->source = htons(12345);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->res1 = 0;
    tcph->doff = sizeof(struct tcphdr) / NET_BYTES_PER_WORD;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htonl(32767);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->id = htonl(54321);
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = saddr;
    iph->daddr = daddr;

    return 0;
}

int init_destsock(struct sockaddr_in* dsock, in_addr_t daddr) {
    dsock->sin_family = AF_INET;
    dsock->sin_addr.s_addr = daddr;
    return 0;
}

int get_payload(char* dgram, unsigned char* key) {
    unsigned char* data = (unsigned char*) (dgram + sizeof(struct iphdr) 
            + sizeof(struct tcphdr));
    struct iphdr* iph = (struct iphdr*) dgram;   
 
    unsigned long unixtime = time(NULL);
    int unixtime_s = snprintf(NULL, 0, "%ld", unixtime);
    unsigned char ptext[unixtime_s];
    snprintf((char*)ptext, unixtime_s, "%ld", unixtime);

    unsigned char iv[PK_IV_BYTES];
    if (gen_iv(iv) == -1) {
        return PK_ERR_CSPRNG;
    }
    int ctext_len;
    unsigned char ctext[PK_CIPHER_BYTES];
    ctext_len = encrypt(ptext, strlen((char*)ptext), key, iv, ctext);
    if (ctext_len == -1) {
        return PK_ERR_ENCRYPT;
    }
    ctext[ctext_len] = '\0';
    strcpy((char*) data, (char*) iv);
    strcpy((char*)(data + PK_IV_BYTES), (char*) ctext);

    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) 
            + PK_IV_BYTES + ctext_len;
    return 0;
}

int set_dport(char* dgram, struct sockaddr_in* dsock, 
        unsigned short dport) {
    struct tcphdr* tcph = (struct tcphdr*) (dgram + sizeof(struct iphdr));

    dsock->sin_port = htons(dport);
    tcph->dest = htons(dport);
    return 0;
}

int send_packet(int sockfd, char* dgram, struct sockaddr_in dsock) {
    struct iphdr* iph = (struct iphdr*) dgram;
    if (sendto(sockfd, dgram, iph->tot_len, 0, (struct sockaddr*) &dsock, 
            sizeof(dsock)) < 0) return PK_ERR_SEND;
    return 0;
}

int knock_ports(unsigned short* ports, int portc, char* dgram, int sockfd, 
        struct sockaddr_in dsock, unsigned char* key) {
    for (int i = 0; i < portc; i++) {
        usleep(10000);
        int payload_err = get_payload(dgram, key);
        if (payload_err != 0) return payload_err;
        int set_dport_err = set_dport(dgram, &dsock, ports[i]);
        if (set_dport_err != 0) return set_dport_err;
        int send_err = send_packet(sockfd, dgram, dsock);
        if (send_err != 0) return send_err;
    }
    return 0;
}

int main(int argc, char** argv) {
    char iface[PK_IFACE_MAX_LEN];
    char host[PK_FQDN_MAX_LEN];
    switch (parse_arguments(argc, argv, iface, host)) {
        case PK_ERR_INSUF_LEN:
            fprintf(stderr, "Insufficient arguments\n");
            fprintf(stderr, "Usage: pkc [iface] [fqdn]\n");
            exit(EXIT_FAILURE);
        case PK_ERR_EXTRA_LEN:
            fprintf(stderr, "Too many arguments\n");
            fprintf(stderr, "Usage: pkc [iface] [fqdn]\n");
            exit(EXIT_FAILURE);
        case PK_ERR_BUF_OF:
            fprintf(stderr, "Argument length exceeds max\n");
            exit(EXIT_FAILURE);
    }

    unsigned char key[PK_KEY_BYTES];
    switch (read_keyfile(key)) {
        case PK_ERR_NP:
            fprintf(stderr, "Could not open key file\n");
            exit(EXIT_FAILURE);
        case PK_ERR_INSUF_LEN:
            fprintf(stderr, "Key is not of sufficient length\n");
            exit(EXIT_FAILURE);
    }
    
    unsigned short ports[PK_MAX_PORTC];
    int portc = 0;
    switch (read_portfile(ports, &portc)) {
        case PK_ERR_NP:
            fprintf(stderr, "Unable to open port file\n");
            exit(EXIT_FAILURE);
        case PK_ERR_EXTRA_LEN:
            fprintf(stderr, "More ports specified than max - ignoring "
                    "extras\n");
            break;
    }

    in_addr_t daddr = 0;
    switch (resolve_fqdn(host, &daddr)) {
        case PK_ERR_NP:
            fprintf(stderr, "Failure resolving FQDN\n");
            exit(EXIT_FAILURE);
    }   

    int sockfd = 0;
    switch (init_socket(&sockfd)) {
        case PK_ERR_SOCK_NEW:
            fprintf(stderr, "Error creating socket\n");
            exit(EXIT_FAILURE);
        case PK_ERR_SOCK_OPT:
            fprintf(stderr, "Error setting socket options\n");
            exit(EXIT_FAILURE);
    }

    int mtu = 0;
    in_addr_t saddr = 0; 
    switch (get_netconfig(sockfd, iface, &mtu, &saddr)) {
        case PK_ERR_IFR_MTU:
            fprintf(stderr, "Cannot get interface mtu\n");
            exit(EXIT_FAILURE);
        case PK_ERR_IFR_ADDR:
            fprintf(stderr, "Cannot get interface address\n");
            exit(EXIT_FAILURE);
    }
   
    char dgram[mtu];
    struct iphdr* iph = NULL;
    struct tcphdr* tcph = NULL;
    init_datagram(saddr, daddr, mtu, dgram, iph, tcph);

    struct sockaddr_in dsock;
    init_destsock(&dsock, daddr);
    
    switch (knock_ports(ports, portc, dgram, sockfd, dsock, key)) {
        case PK_ERR_CSPRNG:
            fprintf(stderr, "Failed to generate IV\n");
            exit(EXIT_FAILURE);
        case PK_ERR_ENCRYPT:
            fprintf(stderr, "\n");
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "\n");
            exit(EXIT_FAILURE);
        case PK_ERR_SEND:
            fprintf(stderr, "Failed to send packet:\n\t%s\n", 
                    strerror(errno));
            exit(EXIT_FAILURE);
    }
    return 0;
}
