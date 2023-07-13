/**
 * @file pkd.h
 * @author Riley Scott Jacob
 * @brief Function declarations for the PK server daemon
 *
 */
#ifndef PKD_H
#define PKD_H

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <pthread.h>
#include <signal.h>

struct conn_state {
    struct in_addr ip;
    int index;
    time_t when;
    struct conn_state* next;
};

/**
 * @brief Handler for user interrupt
 *
 * @param[in] signal Signal to handle
 */
void handle_signal(int signal);

/**
 * @brief Flushes the connection list of stale attempts
 * 
 * @param arg (unused)
 */
void* flush_conn_list(void* arg);

/**
 * @brief Retrieve the connection state for a given knocker IP
 *
 * @param[in] knocker IP address of the knocker
 * @param[out] cs Connection state for the knocker
 */
int get_conn_state(struct in_addr knocker, struct conn_state** cs);

/**
 * @brief Validates the given decrypted message
 *
 * @param[in] ptext Decrypted plaintext message
 *
 * @return Validity of the message
 */
bool validate(unsigned char* ptext);

/**
 * @brief Decrypts a ciphertext using a supplied key and IV
 *
 * @param[in] ctext Ciphertext to decrypt
 * @param[in] ctext_len Length of the ciphertext
 * @param[in] key Key to use in decryption
 * @param[in] iv Initialization vector to use in decryption
 * @param[out] ptext Decrypted plaintext
 */
int decrypt(unsigned char* ctext, int ctext_len, unsigned char* key, 
        unsigned char* iv, unsigned char* ptext);

/**
 * @brief Reads commandline arguments into variables
 *
 * @param[in] argc Number of commandline arguments given by main()
 * @param[in] argv Argument vector given by main()
 * @param[out] iface Name of the user-specified network interface
 */
int parse_arguments(int argc, char** argv, char* iface);

/**
 * @brief Creates a socket and supplies a file descriptor
 *
 * @param[out] sockfd File descriptor for the created socket
 */
int init_socket(int* sockfd);

/**
 * @brief Retrieves configuration for a specified network interface
 *
 * @param[in] sfd Socket file descriptor
 * @param[in] iface Network interface name
 * @param[out] mtu Maximum transmissible unit for the interface
 */
int get_netconfig(int sfd, char* iface, int* mtu);

/**
 * @brief Binds a socket to the given interface
 *
 * @param[in] sfd Socket file descriptor
 * @param[in] iface Name of the interface to bind to
 * @param[out] sll Address of the bound socket
 */
int bind_socket(int sfd, char* iface, struct sockaddr_ll* sll);

/**
 * @brief Monitors for packet recieve errors
 *
 * @param[in] data_s Length of the recieved packet
 * @param[in,out] recv_errors Running counter of consecutive errors
 */
int monitor_recv_errors(int data_s, int* recv_errors);

/**
 * @brief Gives pointers to the IP and TCP headers of a packet
 *
 * @param[in] packet Packet from which to supply headers
 * @param[out] iph Pointer to the IP header
 * @param[out] tcph Pointer to the TCP header
 */
int get_headers(char* packet, struct iphdr** iph, struct tcphdr** tcph);

/**
 * @brief Extracts IV and ciphertext from a packet
 *
 * @param[in] packet Packet from which to extract data
 * @param[out] iv Sent initialization vector
 * @param[out] ctext Sent ciphertext
 */
int get_data(char* packet, unsigned char* iv, unsigned char* ctext);

/**
 * @brief Calls a script to be run when a knocker successfully validates
 *
 * @param[in] ip IP address of the authorized knocker
 */
void authorize(struct in_addr ip);

#endif // PKD_H
