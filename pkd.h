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

#endif // PKD_H
