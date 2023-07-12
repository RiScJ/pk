#include "pk.h"

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
    return PK_SUCCESS;
}

int read_portfile(unsigned short* ports, int* portc) {
    FILE* port_file;
    char* line = NULL;
    size_t len = 0;
    ssize_t read;
    port_file = fopen(PK_FP_PORTS, "r");
    if (port_file == NULL) return PK_ERR_NP;
    while ((read = getline(&line, &len, port_file)) != -1) {
        if (*portc == PK_MAX_PORTC) return PK_ERR_EXTRA_LEN;
        ports[(*portc)++] = atoi(line);
    }
    return PK_SUCCESS;
}
