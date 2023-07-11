#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include <unistd.h>

#define PKD_FLUSH_INTERVAL 60
#define PKD_MAX_RECV_ERRORS 10
#define PKD_LIMIT_RECV_ERRORS
#define PKD_MAX_PORTC 128
#define iface_MAX_LEN 128

volatile sig_atomic_t running = true;

void handle_signal(int signal) {
    if (signal == SIGINT) running = false;
}

struct conn_state {
    struct in_addr ip;
    int index;
    time_t when;
    struct conn_state* next;
};

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

int get_conn_state(struct in_addr knocker, 
                    __attribute__((unused)) struct conn_state** cs) {
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

bool validate(unsigned char* d_msg) {
    unsigned long unixtime = time(NULL);
    int unixtime_s = snprintf(NULL, 0, "%ld", unixtime);
    unsigned char unixtime_str[unixtime_s];
    snprintf((char*)unixtime_str, unixtime_s, "%ld", unixtime);

    if (strcmp((char*)unixtime_str, (char*)d_msg) == 0) return true;
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

int main(int argc, char** argv) {
    signal(SIGINT, handle_signal);

    if (argc < 2) {
        fprintf(stderr, "Must specify interface - aborting\n");
        exit(EXIT_FAILURE);
    }
    
    char iface[iface_MAX_LEN];
    if (strlen(argv[1]) > iface_MAX_LEN) {
        fprintf(stderr, "Interface name too long\n");
        exit(EXIT_FAILURE);
    }
    strcpy(iface, argv[1]);
    
    unsigned char key[32];
    FILE* key_file;
    key_file = fopen("/etc/pk/pk_key", "r");
    if (key_file == NULL) {
        fprintf(stderr, "Could not open key file\n");
        exit(EXIT_FAILURE);
    }
    if (fread(key, sizeof(unsigned char), 32, key_file) < 32) {
        fprintf(stderr, "Key file contents too short\n");
        fclose(key_file);
        exit(EXIT_FAILURE);
    }
    fclose(key_file);    

    unsigned int iv_s = 16;

    unsigned short ports[PKD_MAX_PORTC];
    FILE* port_file;
    char* line = NULL;
    size_t len = 0;
    ssize_t read;
    port_file = fopen("/etc/pk/pk_ports", "r");
    if (port_file == NULL) {
        perror("Unable to open port file\n");
        exit(EXIT_FAILURE);
    }
    int portc = 0;
    while ((read = getline(&line, &len, port_file)) != -1) {
        ports[portc++] = atoi(line);
    }

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sockfd == -1) {
        perror("Error opening socket\n");
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFMTU, &ifr) == -1) {
        perror("Error getting MTU\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    int MTU = ifr.ifr_mtu;
/*    
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        perror("Error getting interface index\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifr.ifr_ifindex;

    if (bind(sockfd, (struct sockaddr*) &sll, sizeof(sll)) == -1) {
        perror("Error binding socket to interface\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
*/
    char packet[MTU];
    struct sockaddr saddr;
    unsigned int saddr_s = sizeof(saddr);
    unsigned int ethhdr_s = sizeof(struct ethhdr);

    if (pthread_mutex_init(&conn_list_lock, NULL) != 0) {
        printf("Mutex init failed\n");
        exit(EXIT_FAILURE);
    }
    
    pthread_t flush_thread;
    if (pthread_create(&flush_thread, NULL, flush_conn_list, NULL) != 0) {
        perror("Error creating flush thread\n");
        close(sockfd);
        pthread_mutex_destroy(&conn_list_lock);
        exit(EXIT_FAILURE);
    }
    
    #ifdef PKD_LIMIT_RECV_ERRORS
    int recv_errors = 0;
    #endif
    while (running) {
        int data_s = recvfrom(sockfd, packet, MTU, 0, &saddr, &saddr_s);
        if (data_s == -1) {
            perror("Packet recieve error\n");
            #ifdef PKD_LIMIT_RECV_ERRORS
            recv_errors++;
            if (recv_errors > PKD_MAX_RECV_ERRORS) {
                fprintf(stderr, "Exceeded max consecutive recieve "
                        "errors\n");    
                close(sockfd);
                pthread_mutex_destroy(&conn_list_lock);
                exit(EXIT_FAILURE);    
            }
            #endif
            continue;
        }
        recv_errors = 0;
        struct iphdr* iph = (struct iphdr*)(packet + ethhdr_s);
        if (iph->protocol != IPPROTO_TCP) continue;
        unsigned int iphdr_s = iph->ihl * 4;
        struct tcphdr* tcph = (struct tcphdr*) (packet + iphdr_s 
                + ethhdr_s);
        unsigned int tcphdr_s = tcph->doff * 4;

        if ( tcph->ack) continue;
        if (!tcph->syn) continue;

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
        if (ntohs(tcph->dest) == ports[state->index]) {
            
            unsigned char* e_msg = (unsigned char*) (packet + ethhdr_s 
                    + iphdr_s + tcphdr_s + iv_s);
            unsigned int e_msg_s = ntohs(iph->tot_len) - iphdr_s 
                    - tcphdr_s - iv_s;
            if (e_msg_s == 0) {
                state->index = 0;
                printf("\u2717\n");
                continue;
            }
            unsigned char* iv = (unsigned char*) (packet + ethhdr_s 
                    + iphdr_s + tcphdr_s);
            unsigned char d_msg[128];
            int d_msg_s = decrypt(e_msg, (int) e_msg_s, key, iv, d_msg);
            if (d_msg_s == -1) {
                ERR_print_errors_fp(stderr);
                printf("\n");
                fprintf(stderr, "Bad decrypt - resetting...\n");
                state->index = 0;
                continue;
            }
            if (!validate(d_msg)) {
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
