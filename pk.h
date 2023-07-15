/**
 * @file pk.h
 * @author Riley Scott Jacob
 * @brief Function declarations used by PKC and PKD
 *
 */
#ifndef PK_H
#define PK_H

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <time.h>

#include "pk_err.h"
#include "pk_defs.h"

/**
 * @brief Reads encryption key in from configuration file
 *
 * Loads the encryption key stored in the configuration file located
 * at PK_FP_KEY.
 *
 * @param[out] key Key read in from the configuration file
 */
int read_keyfile(unsigned char* key);

/**
 * @brief Reads port sequence to knock from configuration file
 * 
 * Loads the sequence of ports to knock in from the configuration file
 * located at PK_FP_PORTS.
 *
 * @param[out] ports Sequence of ports to knock
 * @param[out] portc Number of ports to knock
 */
int read_portfile(unsigned short* ports, int* portc);

/**
 * @brief Retrieves configuration for a specified network interface
 *
 * @param[in] sfd Socket file descriptor
 * @param[in] iface Network interface name
 * @param[out] mtu Maximum transmissible unit for the interface
 * @param[out] s_addr IPv4 address for the interface
 */
int get_netconfig(int sfd, char* iface, int* mtu, in_addr_t* s_addr);

#endif // PK_H
