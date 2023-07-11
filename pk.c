#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>

#define NET_BYTES_PER_WORD 4

#define PK_IFACE_MAX_LEN 128
#define PK_FQDN_MAX_LEN 128
#define PK_MAX_PORTC 128
#define PK_ARGC 3
#define PK_ARGN_IFACE 1
#define PK_ARGN_FQDN 2
#define PK_KEY_BYTES 32
#define PK_IV_BYTES 16

#define PK_FP_KEY "/etc/pk/pk_key"
#define PK_FP_PORTS "/etc/pk/pk_ports"

#define PK_ERR_INSUF_LEN 1
#define PK_ERR_EXTRA_LEN 2
#define PK_ERR_BUF_OF 3
#define PK_ERR_NP 4
#define PK_ERR_SOCK 5
#define PK_ERR_IFR_MTU 6
#define PK_ERR_IFR_ADDR 7

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
    return RAND_bytes(iv, sizeof(iv));
}

int parse_arguments(int argc, char** argv, char* iface, char* fqdn) {
    if (argc < PK_ARGC) return PK_ERR_INSUF_LEN;
    if (argc > PK_ARGC) return PK_ERR_EXTRA_LEN;
    if (strlen(argv[PK_ARGN_IFACE]) > PK_IFACE_MAX_LEN 
            || strlen(argv[PK_ARGN_FQDN]) > PK_FQDN_MAX_LEN)
                    return PK_ERR_BUF_OF; 
    
    strcpy(iface, argv[PK_ARGN_IFACE]);
    strcpy(fqdn, argv[PK_ARGN_FQDN]);
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
    if (*sockfd == -1) return PK_ERR_SOCK;
    return 0;
}

int get_netconfig(int sfd, char* iface, int* MTU, 
        in_addr_t* s_addr) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sfd, SIOCGIFMTU, &ifr) == -1) return PK_ERR_IFR_MTU;
    *MTU = ifr.ifr_mtu;
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(sfd, SIOCGIFADDR, &ifr) == -1) return PK_ERR_IFR_ADDR;
    struct sockaddr_in* sin;
    sin = (struct sockaddr_in*) &ifr.ifr_addr;
    *s_addr = sin->sin_addr.s_addr;
    return 0;
}

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
    return 0;
}

int read_portfile(unsigned short* ports, int* portc) {
    FILE* port_file;
    char* line = NULL;
    size_t len = 0;
    ssize_t read;
    port_file = fopen(PK_FP_PORTS, "r");
    if (port_file == NULL) return PK_ERR_NP;
    while ((read = getline(&line, &len, port_file)) != -1) {
        ports[(*portc)++] = atoi(line);
    }
    return 0;
}

int init_datagram(int mtu, char* dgram, struct iphdr** iph, 
        struct tcphdr** tcph) { 
    *iph = (struct iphdr*) dgram;
    *tcph = (struct tcphdr*) (dgram + sizeof(struct iphdr));
    memset(dgram, 0, mtu);
    
    (*tcph)->source = htons(12345);
    (*tcph)->seq = 0;
    (*tcph)->ack_seq = 0;
    (*tcph)->res1 = 0;
    (*tcph)->doff = sizeof(struct tcphdr) / NET_BYTES_PER_WORD;
    (*tcph)->fin = 0;
    (*tcph)->syn = 1;
    (*tcph)->rst = 0;
    (*tcph)->psh = 0;
    (*tcph)->ack = 0;
    (*tcph)->urg = 0;
    (*tcph)->window = htonl(32767);
    (*tcph)->check = 0;
    (*tcph)->urg_ptr = 0;

    (*iph)->ihl = 5;
    (*iph)->version = 4;
    (*iph)->tos = 0;
    (*iph)->id = htonl(54321);
    (*iph)->ttl = 255;
    (*iph)->protocol = IPPROTO_TCP;
    (*iph)->check = 0;

    return 0;
}

int init_destsock(struct sockaddr_in* dsock, in_addr_t daddr) {
    dsock->sin_family = AF_INET;
    dsock->sin_addr.s_addr = daddr;
    return 0;
}

int main(int argc, char** argv) {
    char iface[PK_IFACE_MAX_LEN];
    char host[PK_FQDN_MAX_LEN];
    switch (parse_arguments(argc, argv, iface, host)) {
        case PK_ERR_INSUF_LEN:
            fprintf(stderr, "Insufficient arguments\n");
            fprintf(stderr, "Usage: pk [iface] [fqdn]\n");
            exit(EXIT_FAILURE);
        case PK_ERR_EXTRA_LEN:
            fprintf(stderr, "Too many arguments\n");
            fprintf(stderr, "Usage: pk [iface] [fqdn]\n");
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
            perror("Unables to open port file\n");
            exit(EXIT_FAILURE);
    }

    in_addr_t daddr = 0;
    switch(resolve_fqdn(host, &daddr)) {
        case PK_ERR_NP:
            fprintf(stderr, "Failure resolving FQDN\n");
            exit(EXIT_FAILURE);
    }   

    int sockfd = 0;
    switch(init_socket(&sockfd)) {
        case PK_ERR_SOCK:
            perror("Error creating socket\n");
            exit(EXIT_FAILURE);
    }

    int MTU = 0;
    in_addr_t src_addr = 0; 
    switch(get_netconfig(sockfd, iface, &MTU, &src_addr)) {
        case PK_ERR_IFR_MTU:
            perror("Cannot get interface MTU\n");
            exit(EXIT_FAILURE);
        case PK_ERR_IFR_ADDR:
            perror("Cannot get interface address\n");
            exit(EXIT_FAILURE);
    }
   
    char datagram[MTU];
    struct iphdr* iph = NULL;
    struct tcphdr* tcph = NULL;
    init_datagram(MTU, datagram, &iph, &tcph);

    struct sockaddr_in dsock;
    init_destsock(&dsock, daddr);
    
    iph->saddr = src_addr;
    iph->daddr = daddr;

    int one = 1;
    const int* one_a = &one;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, one_a, 
            sizeof(one)) < 0) {
        perror("setsockopt() error\n");
        exit(EXIT_FAILURE);
    }    

    unsigned char iv[16];
    for (int i = 0; i < portc; i++) {
        if (gen_iv(iv) == -1) {
            fprintf(stderr, "Failed to generate IV\n");
            exit(EXIT_FAILURE);
        }
        
        unsigned long unixtime = time(NULL);
        int unixtime_s = snprintf(NULL, 0, "%ld", unixtime);
        unsigned char ptext[unixtime_s];
        snprintf((char*)ptext, unixtime_s, "%ld", unixtime);
        
        unsigned char* data = (unsigned char*) (datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) 
                + 16);
        unsigned char* iv_p = (unsigned char*) (datagram + sizeof(struct iphdr) + sizeof(struct tcphdr));
        memcpy(iv_p, iv, 16);
        unsigned char ctext[128];
        int ctext_len;
        ctext_len = encrypt(ptext, strlen((char*)ptext), key, iv, ctext);
        if (ctext_len == -1) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        unsigned int data_s = (unsigned int) ctext_len;
        ctext[ctext_len] = '\0';
        strcpy((char*)data, (char*)ctext);
        
        tcph->dest = htons(ports[i]);    
        iph->tot_len = iph->ihl*4 + sizeof(struct tcphdr) + data_s + 16;
        
        if (sendto(sockfd, datagram, iph->tot_len, 0, 
                (struct sockaddr*) &dsock, sizeof(dsock)) < 0) {
            perror("sendto() error\n");
            exit(EXIT_FAILURE);
        } else {
            printf("Sent packet\n");
        }
    }
    return 0;
}
