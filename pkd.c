#include "pk.h"
#include "pkd.h"

volatile sig_atomic_t running = true;

void handle_signal(int signal) {
    if (signal == SIGINT) running = false;
}

struct conn_state* conn_list = NULL;

pthread_mutex_t conn_list_lock;

void* flush_conn_list(void* arg) {
    (void) arg;
    while (running) {
        sleep(PKD_FLUSH_INTERVAL);

        pthread_mutex_lock(&conn_list_lock);

        struct conn_state* state = conn_list;
        struct conn_state* prev_state = NULL;

        while (state != NULL) {
            if (difftime(time(NULL), state->when) > PKD_FLUSH_INTERVAL) {
                if (prev_state != NULL) {
                    prev_state->next = state->next;
                } else {
                    conn_list = state->next;
                }
                state = state->next;
            } else {
                prev_state = state;
                state = state->next;
            }
        }
        pthread_mutex_unlock(&conn_list_lock);
    }
    return NULL;
}

int get_conn_state(struct in_addr knocker, struct conn_state** cs) {
    pthread_mutex_lock(&conn_list_lock);
    struct conn_state* state;
    for (state = conn_list; state != NULL; state = state->next) {
        if (state->ip.s_addr == knocker.s_addr) {
            pthread_mutex_unlock(&conn_list_lock);    
            *cs = state;
            return 0;
        }
    }
    state = malloc(sizeof(struct conn_state));
    if (state == NULL) {
        perror("Memory allocation error\n");
        return -1;
    }
    state->ip.s_addr = knocker.s_addr;
    state->index = 0;
    state->when = time(NULL);
    state->next = conn_list;
    conn_list = state;
    pthread_mutex_unlock(&conn_list_lock);
    *cs = state;
    return 0;
}

bool validate(unsigned char* ptext) {
    unsigned long unixtime = time(NULL);
    int unixtime_s = snprintf(NULL, 0, "%ld", unixtime);
    unsigned char unixtime_str[unixtime_s];
    snprintf((char*)unixtime_str, unixtime_s, "%ld", unixtime);

    if (strcmp((char*)unixtime_str, (char*)ptext) == 0) return true;
    return false;
}

int decrypt(unsigned char* ctext, int ctext_len, unsigned char* key, 
            unsigned char* iv, unsigned char* ptext) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int ptext_len;
    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        return -1;
    }
    if (1 != EVP_DecryptUpdate(ctx, ptext, &len, ctext, ctext_len)) {
        return -1;
    }
    ptext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, ptext + len, &len)) return -1;
    ptext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ptext_len;
}

int parse_arguments(int argc, char** argv, char* iface) {
    if (argc < PKD_ARGC) return PK_ERR_INSUF_LEN;
    if (argc < PKD_ARGC) return PK_ERR_EXTRA_LEN;
    if (strlen(argv[PKD_ARGN_IFACE]) > PK_IFACE_MAX_LEN) {
        return PK_ERR_BUF_OF;
    }
    strcpy(iface, argv[PKD_ARGN_IFACE]);
    return PK_SUCCESS;
}

int init_socket(int* sockfd) {
    *sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (*sockfd == -1) return PK_ERR_SOCK_NEW;
    return PK_SUCCESS;
}

int bind_socket(int sfd, char* iface, struct sockaddr_ll* sll) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sfd, SIOCGIFINDEX, &ifr) == -1) return PK_ERR_IFR_INDEX;
    memset(sll, 0, sizeof(*sll));
    sll->sll_family = AF_PACKET;
    sll->sll_protocol = htons(ETH_P_ALL);
    sll->sll_ifindex = ifr.ifr_ifindex;
    if (bind(sfd, (struct sockaddr*) sll, sizeof(*sll)) == -1) {
        return PK_ERR_SOCK_BIND;
    }
    return PK_SUCCESS;
}

int monitor_recv_errors(int data_s, int* recv_errors) {
    if (data_s == -1) {
        fprintf(stderr, "Packet recieve error\n");
        (*recv_errors)++;
        if (*recv_errors > PKD_MAX_RECV_ERRORS) return PK_ERR_RECV_MAX;
        return PK_ERR_RECV;
    }
    *recv_errors = 0;
    return PK_SUCCESS;
}

int get_headers(char* packet, struct iphdr** iph, struct tcphdr** tcph) { 
    unsigned int eh_s = sizeof(struct ethhdr);
    
    *iph = (struct iphdr*) (packet + eh_s);
    unsigned int ih_s = (*iph)->ihl * 4;    

    *tcph = (struct tcphdr*) (packet + eh_s + ih_s);
    
    if (*iph == NULL || *tcph == NULL) {
        return PK_ERR_NP;
    }

    return PK_SUCCESS;
}

int get_data(char* packet, unsigned char* iv, unsigned char* ctext) {
    unsigned int eh_s = sizeof(struct ethhdr);
    unsigned int ih_s = sizeof(struct iphdr);
    unsigned int th_s = sizeof(struct tcphdr);

    struct iphdr* iph = (struct iphdr*) (packet + eh_s);
    unsigned int len = ntohs(iph->tot_len);

    unsigned char* iv_p = (unsigned char*) (packet + eh_s + ih_s + th_s);
    unsigned char* ctext_p = (unsigned char*) (packet + eh_s + ih_s + th_s 
            + PK_IV_BYTES);
    unsigned int ctext_len = len - ih_s - th_s 
            - PK_IV_BYTES;

    if (ctext_len == 0) return PK_ERR_INSUF_LEN;
    if (ctext_len >= PK_CIPHER_BYTES -1) return PK_ERR_EXTRA_LEN;

    strncpy((char*) iv, (char*) iv_p, PK_IV_BYTES);
    strncpy((char*) ctext, (char*) ctext_p, ctext_len);
    ctext[ctext_len] = '\0';
    
    return PK_SUCCESS;
}

int authorize(struct in_addr ip, in_addr_t saddr) {
    usleep(PKD_DELAY_AUTH);
    in_addr_t daddr = ip.s_addr;

    int rsfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    char dgram[PKD_RESP_BYTES];
    
    struct iphdr* iph = (struct iphdr*) dgram;
    struct tcphdr* tcph = (struct tcphdr*) (dgram + sizeof(struct iphdr));
    memset(dgram, 0, PKD_RESP_BYTES);

    char* data = dgram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    strcpy(data, "");


    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PKC_LSOCK_PORT);
    sin.sin_addr.s_addr = daddr;

    tcph->source = htons(PKC_LSOCK_PORT);
    tcph->dest = htons(PKC_LSOCK_PORT);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->res1 = 0;
    tcph->doff = sizeof(struct tcphdr) / NET_BYTES_PER_WORD;
    tcph->fin = 0;
    tcph->syn = 0;
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
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->saddr = saddr;
    iph->daddr = daddr;

    if (setsockopt(rsfd, IPPROTO_IP, IP_HDRINCL, &sin, sizeof(sin)) < 0) {
        return PK_ERR_SOCK_OPT;
    }

    if(sendto(rsfd, dgram, iph->tot_len, 0, (struct sockaddr*) &sin, 
            sizeof(sin)) == -1) {
        return PK_ERR_SEND;
    }
    printf("Auth resp sent\n");

    char call[PKD_CALL_BYTES];
    sprintf(call, PKD_FP_AUTH_SH " %s", inet_ntoa(ip));
    system(call);
    return PK_SUCCESS;
}

int main(int argc, char** argv) {
    signal(SIGINT, handle_signal);

    char iface[PK_IFACE_MAX_LEN];
    switch (parse_arguments(argc, argv, iface)) {
        case PK_ERR_INSUF_LEN:
            fprintf(stderr, "Insufficient arguments\n");
            fprintf(stderr, "Usage: pkd [iface]\n");
            exit(EXIT_FAILURE);
        case PK_ERR_EXTRA_LEN:
            fprintf(stderr, "Too many arguments\n");
            fprintf(stderr, "Usage: pkd [iface]\n");
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

    int sockfd = 0;
    switch (init_socket(&sockfd)) {
        case PK_ERR_SOCK_NEW:
            fprintf(stderr, "Error opening socket\n");
            exit(EXIT_FAILURE);
    }

    int mtu = 0;
    in_addr_t rsaddr = 0;
    switch (get_netconfig(sockfd, iface, &mtu, &rsaddr)) {
        case PK_ERR_IFR_MTU:
            fprintf(stderr, "Cannot get interface mtu\n");
            exit(EXIT_FAILURE);
        case PK_ERR_IFR_ADDR:
            fprintf(stderr, "Cannot get interface address\n");
            exit(EXIT_FAILURE);
    }

    struct sockaddr_ll sll; 
    #ifndef PKD_LISTEN_LO
    switch (bind_socket(sockfd, iface, &sll)) {
        case PK_ERR_IFR_INDEX:
            fprintf(stderr, "Error getting interface index\n");
            exit(EXIT_FAILURE);
        case PK_ERR_SOCK_BIND:
            fprintf(stderr, "Error binding socket to interface\n");
            exit(EXIT_FAILURE);
    }
    #endif
    socklen_t saddr_s = sizeof(struct sockaddr);

    char packet[mtu];

    if (pthread_mutex_init(&conn_list_lock, NULL) != 0) {
        fprintf(stderr, "Mutex init failed\n");
        exit(EXIT_FAILURE);
    }
    
    pthread_t flush_thread;
    if (pthread_create(&flush_thread, NULL, flush_conn_list, NULL) != 0) {
        fprintf(stderr, "Error creating flush thread\n");
        close(sockfd);
        pthread_mutex_destroy(&conn_list_lock);
        exit(EXIT_FAILURE);
    }
    
    int recv_errors = 0;
    while (running) {
        int data_s = recvfrom(sockfd, packet, mtu, 0, 
                (struct sockaddr*) &sll, &saddr_s);

        switch (monitor_recv_errors(data_s, &recv_errors)) {
            case PK_ERR_RECV_MAX:
                fprintf(stderr, "Exceeded max consecutive recieve "
                        "errors\n");
                close(sockfd);
                pthread_mutex_destroy(&conn_list_lock);
                exit(EXIT_FAILURE);
            case PK_ERR_RECV:
                continue;
        }

        struct iphdr* iph = NULL;
        struct tcphdr* tcph = NULL;
        switch (get_headers(packet, &iph, &tcph)) {
            case PK_ERR_NP:
                fprintf(stderr, "Unable to get headers\n");
                continue;
        }
        if (iph->protocol != IPPROTO_TCP) continue;
        if ( tcph->ack) continue;
        if (!tcph->syn) continue;
       
        unsigned int iphdr_s = iph->ihl * 4;
        unsigned int tcphdr_s = tcph->doff * 4;
        unsigned int tot_len = ntohs(iph->tot_len);
        unsigned int ctext_len = tot_len - iphdr_s - tcphdr_s 
                - PK_IV_BYTES;

        struct in_addr knocker;
        knocker.s_addr = iph->saddr;
        
        struct conn_state* state = NULL;
        if (get_conn_state(knocker, &state) == -1) {
            close(sockfd);
            pthread_mutex_destroy(&conn_list_lock);
            exit(EXIT_FAILURE);
        }
        printf("[SYN] :: %-15s :: %5d :: ", inet_ntoa(state->ip), 
                ntohs(tcph->dest));
        
        unsigned char iv[PK_IV_BYTES];
        unsigned char ctext[PK_CIPHER_BYTES];
        switch (get_data(packet, iv, ctext)) {
            case PK_ERR_INSUF_LEN:
                state->index = 0;
                printf("\u2717\n");
                continue;
            case PK_ERR_EXTRA_LEN:
                state->index = 0;
                printf("\u2717\n");
                continue;
        }
        
        if (ntohs(tcph->dest) == ports[state->index]) {    
            unsigned char ptext[PK_CIPHER_BYTES];
            int ptext_len = decrypt(ctext, (int) ctext_len, key, iv, 
                    ptext);
            if (ptext_len == -1) {
                ERR_print_errors_fp(stderr);
                printf("\n");
                fprintf(stderr, "Bad decrypt - resetting...\n");
                state->index = 0;
                continue;
            }
            if (!validate(ptext)) {
                state->index = 0;
                printf("\u2717\n");
                continue;
            } 
            state->index++;
            for (int i = 0; i < state->index; i++) {
                printf("\u2713");
            }
            printf("\n");
            if (state->index == portc) {
                printf("[ \u2713 ] :: %s\n", inet_ntoa(state->ip));
                switch (authorize(state->ip, rsaddr)) {
                    case PK_ERR_SOCK_OPT:
                        fprintf(stderr, "Could not set socket options\n");
                        continue;
                    case PK_ERR_SEND:
                        fprintf(stderr, "Could not send auth ack\n");
                        continue;
                }
                state->index = 0;
            }
        } else {
            state->index = 0;
            printf("\u2717\n");
        }
        state->when = time(NULL);
    }
    close(sockfd);
    pthread_cancel(flush_thread);
    pthread_mutex_destroy(&conn_list_lock);
    printf("\n");
    return 0;
}
