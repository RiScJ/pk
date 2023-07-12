#ifndef PK_H
#define PK_H

#include <arpa/inet.h>
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

int read_keyfile(unsigned char* key);
int read_portfile(unsigned short* ports, int* portc);

#endif // PK_H
