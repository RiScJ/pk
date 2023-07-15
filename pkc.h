/**
 * @file pkc.h
 * @author Riley Scott Jacob
 * @brief Function declarations for the PK client program
 *
 */
#ifndef PKC_H
#define PKC_H

#include <arpa/nameser.h>
#include <openssl/rand.h>
#include <resolv.h>
#include <netdb.h>

/**
 * @brief Encrypts a message using AES-256-CBC
 *
 * @param[in] ptext Unencrypted plaintext
 * @param[in] ptext_len Length of the plaintext
 * @param[in] key Key to use to encrypt the message
 * @param[in] iv Initialization vector used in encryption
 * @param[out] ctext Encrypted ciphertext
 */
int encrypt(unsigned char* ptext, int ptext_len, unsigned char* key, 
        unsigned char* iv, unsigned char* ctext);

/**
 * @brief Generates a CSPR initialization vector
 * 
 * @param[out] iv Generated initialization vector
 */
int gen_iv(unsigned char* iv);

/**
 * @brief Reads commandline arguments into variables
 * 
 * @param[in] argc Number of arguments supplied by main(int, char**)
 * @param[in] argv Argument vector supplied by main(int, char**)
 * @param[out] iface Network interface name
 * @param[out] fqdn Target fully-qualified domain name
 */
int parse_arguments(int argc, char** argv, char* iface, char* fqdn);

/**
 * @brief Resolves FQDN to an IP address
 * 
 * @param[in] fqdn FQDN to resolve
 * @param[out] daddr Resolved IP address
 */
int resolve_fqdn(char* fqdn, in_addr_t* daddr);

/**
 * @brief Initializes a raw socket
 *
 * @param[out] sockfd File descriptor for created socket
 */
int init_socket(int* sockfd);

/**
 * @brief Retrieves configuration for a specified network interface
 *
 * @param[in] sfd Socket file descriptor
 * @param[in] iface Network interface name
 * @param[out] mtu Maximum transmissible unit for the interface
 * @param[out] s_addr IPv4 address for the interface
 */
//int get_netconfig(int sfd, char* iface, int* mtu, in_addr_t* s_addr);

/**
 * @brief Initializes the raw IP packet which will be transmitted
 *
 * Creates a packet of size mtu, and specifies pointers to the IP and
 * TCP headers. The headers have relevant parameters set that the server
 * program will be listening for.
 *
 * @param[in] saddr Source address for the packet
 * @param[in] daddr Destination address for the packet
 * @param[in] mtu Maximum transmissible unit for the network
 * @param[out] dgram Initialized packet
 * @param[out] iph Pointer to the IP header
 * @param[out] tcph Pointer to the TCP header
 */
int init_datagram(in_addr_t saddr, in_addr_t daddr, int mtu, char* dgram, 
        struct iphdr* iph, struct tcphdr* tcph);

/**
 * @brief Initializes the destination socket
 * 
 * @param[out] dsock Destination socket
 * @param[in] daddr Address of the destination socket
 */
int init_destsock(struct sockaddr_in* dsock, in_addr_t daddr);

/**
 * @brief Creates an encrypted payload to be sent over the network
 *
 * @param[in,out] dgram Packet which will contain payload after call
 * @param[in] key Key to be used to create the encrypted payload
 */
int get_payload(char* dgram, unsigned char* key);

/**
 * @brief Sets the port on the destination socket
 * 
 * Fetches the TCP header contained within the supplied datagram, and 
 * modified its destination to dport; also modifies destination port of
 * supplied socket.
 *
 * @param[in,out] dgram Packet containing information to be changed
 * @param[in,out] dsock Destination socket to be modified
 * @param[in] dport Port to change destination to
 */
int set_dport(char* dgram, struct sockaddr_in* dsock, 
        unsigned short dport);

/**
 * @brief Sends a packet over the network
 *
 * @param[in] sockfd Socket file descriptor
 * @param[in] dgram Packet to be transmitted
 * @param[in] dsock Destination socket address
 */
int send_packet(int sockfd, char* dgram, struct sockaddr_in dsock);

/**
 * @brief Conducts the port knocking sequence
 *
 * @param[in] ports Sequence of ports to knock
 * @param[in] portc Number of ports in the sequence
 * @param[in] dgram Packet template which will be sent during the knocks
 * @param[in] sockfd Socket file descriptor
 * @param[in] dsock Destination socket address
 * @param[in] key Key which will be used to encrypt the packet payload
 * @param[in] lsfd File descriptor for socket to listen for response on
 * @param[in] lsock Address of listening socket
 * @param[in] mtu Network interface MTU
 */
int knock_ports(unsigned short* ports, int portc, char* dgram, 
        int sockfd, struct sockaddr_in dsock, unsigned char* key, 
        int lsfd, struct sockaddr_in* lsock, int mtu);

#endif // PKC_H
