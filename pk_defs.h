#ifndef PK_DEFS_H
#define PK_DEFS_H


#define NET_BYTES_PER_WORD      4

#define PK_FP_KEY               "/etc/pk/pk_key"
#define PK_FP_PORTS             "/etc/pk/pk_ports"

#define PK_IFACE_MAX_LEN        128
#define PK_FQDN_MAX_LEN         128
#define PK_MAX_PORTC            128

#define PK_KEY_BYTES            32
#define PK_IV_BYTES             16
#define PK_CIPHER_BYTES         128

#define PKC_ARGC                3
#define PKC_ARGN_IFACE          1
#define PKC_ARGN_FQDN           2
#define PKC_DELAY_PACKET        10000
#define PKC_DELAY_RETRY         1
#define PKC_LSOCK_PORT          12345

#define PKD_ARGC                2
#define PKD_ARGN_IFACE          1
#define PKD_FLUSH_INTERVAL      60
#define PKD_MAX_RECV_ERRORS     10
#define PKD_LISTEN_LO
#define PKD_FP_AUTH_SH          "/etc/pk/pk_auth"
#define PKD_CALL_BYTES          128
#define PKD_RESP_BYTES          1028
#define PKD_DELAY_AUTH          100000

#endif // PK_DEFS_H
