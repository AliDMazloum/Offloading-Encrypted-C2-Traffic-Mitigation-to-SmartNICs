/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <getopt.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_regexdev.h>

#include <rte_crypto.h>
#include <rte_cryptodev.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8192
#define BURST_SIZE 1000

#define MAX_FILE_NAME 255
#define MAX_SERVER_NAME 255
#define MBUF_CACHE_SIZE 256
#define MBUF_SIZE (1 << 8)

#define JUMBO_FRAME_MAX_SIZE 0x2600

#define P4_packet 5555

typedef struct
{
    rte_be32_t words[8];
} uint256_t;

typedef struct
{
    uint8_t bytes[3];
} uint24_t;

uint16_t uint24_to_16(uint24_t value);
uint16_t uint24_to_16(uint24_t value){
    return((uint16_t)value.bytes[1] << 8)| value.bytes[2];
}

struct tls_hdr
{
    uint8_t type;
    uint16_t version;
    uint16_t len;
};

struct rte_tls_hdr
{
    uint8_t type;
    rte_be16_t version;
    rte_be16_t length;
} __rte_packed;

struct rte_tls_hello_hdr
{
    uint8_t type;
    uint24_t len;
    rte_be16_t version;
    uint256_t random;
} __rte_packed;

struct rte_tls_session_hdr
{
    uint8_t len;
} __rte_packed;

struct rte_tls_cipher_hdr
{
    uint16_t len;
} __rte_packed;

struct rte_tls_compression_hdr
{
    uint8_t len;
} __rte_packed;

struct rte_tls_ext_len_hdr
{
    uint16_t len;
} __rte_packed;

struct rte_tls_ext_hdr
{
    uint16_t type;
    uint16_t len;
} __rte_packed;

struct rte_ctls_ext_sni_hdr
{
    uint16_t sni_list_len;
    uint8_t type;
    uint16_t sni_len;
} __rte_packed;

struct rte_server_name
{
    uint16_t name;
} __rte_packed;

struct job_ctx
{
    struct rte_mbuf *mbuf;
};

struct qps_per_lcore
{
    unsigned int lcore_id;
    int socket;
    uint16_t qp_id_base;
    uint16_t nb_qps;
};

struct regex_conf
{
    uint32_t nb_jobs;
    bool perf_mode;
    uint8_t nb_max_matches;
    uint32_t nb_qps;
    uint16_t qp_id_base;
    char *data_buf;
    long data_len;
    long job_len;
    uint32_t nb_segs;
    uint32_t match_mode;
};

struct rte_client_hello_dpdk_hdr
{
    uint8_t type;
    uint16_t len;
    uint16_t exts_num;
} __rte_packed;

struct rte_server_hello_dpdk_hdr
{
    uint8_t type;
    uint16_t len;
    uint16_t exts_num;
    uint16_t version;
} __rte_packed;

static long
read_file(char *file, char **buf)
{
    FILE *fp;
    long buf_len = 0;
    size_t read_len;
    int res = 0;

    fp = fopen(file, "r");
    if (!fp)
        return -EIO;
    if (fseek(fp, 0L, SEEK_END) == 0)
    {
        buf_len = ftell(fp);
        if (buf_len == -1)
        {
            res = EIO;
            goto error;
        }
        *buf = rte_malloc(NULL, sizeof(char) * (buf_len + 1), 4096);
        if (!*buf)
        {
            res = ENOMEM;
            goto error;
        }
        if (fseek(fp, 0L, SEEK_SET) != 0)
        {
            res = EIO;
            goto error;
        }
        read_len = fread(*buf, sizeof(char), buf_len, fp);
        if (read_len != (unsigned long)buf_len)
        {
            res = EIO;
            goto error;
        }
    }
    fclose(fp);
    return buf_len;
error:
    printf("Error, can't open file %s\n, err = %d", file, res);
    if (fp)
        fclose(fp);
    rte_free(*buf);
    return -res;
}

/* >8 End of launching function on lcore. */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    static struct rte_eth_conf port_conf = {
        .rxmode = {
            .mtu = JUMBO_FRAME_MAX_SIZE,
        },
    };
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxconf;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    rte_eth_promiscuous_enable(port);

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0)
    {
        printf("Error during getting device (port %u) info: %s\n",
               port, strerror(-retval));

        return retval;
    }

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;
    rxconf = dev_info.default_rxconf;

    for (q = 0; q < rx_rings; q++)
    {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                        rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; q++)
    {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }
    retval = rte_eth_dev_start(port);
    if (retval < 0)
    {
        return retval;
    }
    return 0;
}

static inline int
regex_init(void)
{

    uint16_t id;
    uint16_t qp_id;
    uint16_t num_devs;
    int retval;
    long rules_len;
    char *rules = NULL;
    struct rte_regexdev_info info;
    struct rte_regexdev_config dev_conf = {
        .nb_queue_pairs = 1,
        .nb_groups = 1,
    };
    struct rte_regexdev_qp_conf qp_conf = {
        .nb_desc = 1024,
        .qp_conf_flags = 0,
    };
    char rules_file[MAX_FILE_NAME] = "/home/ubuntu/rof/.rof2.binary";

    rules_len = read_file(rules_file, &rules);
    if (rules_len < 0)
    {
        printf("Error, can't read rules files.\n");
        retval = -EIO;
        goto error;
    }

    num_devs = rte_regexdev_count();
    for (id = 0; id < num_devs; id++)
    {
        retval = rte_regexdev_info_get(id, &info);
        if (retval != 0)
        {
            printf("Error, can't get device info.\n");
            goto error;
        }
        printf(":: initializing dev: %d\n", id);
        if (info.regexdev_capa & RTE_REGEXDEV_SUPP_MATCH_AS_END_F)
            dev_conf.dev_cfg_flags |=
                RTE_REGEXDEV_CFG_MATCH_AS_END_F;
        dev_conf.nb_max_matches = info.max_matches;
        dev_conf.nb_rules_per_group = info.max_rules_per_group;
        dev_conf.rule_db_len = rules_len;
        dev_conf.rule_db = rules;
        retval = rte_regexdev_configure(id, &dev_conf);
        if (retval < 0)
        {
            printf("Error, can't configure device %d.\n", id);
            goto error;
        }
        if (info.regexdev_capa & RTE_REGEXDEV_CAPA_QUEUE_PAIR_OOS_F)
            qp_conf.qp_conf_flags |=
                RTE_REGEX_QUEUE_PAIR_CFG_OOS_F;
        for (qp_id = 0; qp_id < 1; qp_id++)
        {
            retval = rte_regexdev_queue_pair_setup(id, qp_id,
                                                   &qp_conf);
            if (retval < 0)
            {
                printf("Error, can't setup queue pair %u for "
                       "device %d.\n",
                       qp_id, id);
                goto error;
            }
        }
        printf(":: initializing device: %d done\n", id);
    }
    rte_free(rules);
    return 0;

error:
    rte_free(rules);
    return retval;
}

#define MAX_NAME_LENGTH 100
char **read_names_from_file(const char *filename, int *num_names);
char **read_names_from_file(const char *filename, int *num_names)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        perror("Error opening file");
        return NULL;
    }

    char **names = NULL;
    *num_names = 0;
    char line[MAX_NAME_LENGTH];

    while (fgets(line, sizeof(line), file) != NULL)
    {
        // Remove newline character if present
        line[strcspn(line, "\n")] = '\0';

        // Allocate memory for the new name
        char *new_name = malloc(strlen(line) + 1);
        if (new_name == NULL)
        {
            fprintf(stderr, "Memory allocation failed for name: %s\n", line);
            fclose(file);

            // Free all previously allocated names on error
            for (int i = 0; i < *num_names; i++)
            {
                free(names[i]);
            }
            free(names);

            return NULL;
        }

        // Copy the name into allocated memory
        strcpy(new_name, line);

        // Resize the names array to hold the new name
        char **temp = realloc(names, (*num_names + 1) * sizeof(char *));
        if (temp == NULL)
        {
            fprintf(stderr, "Memory reallocation failed\n");
            free(new_name);
            fclose(file);

            // Free all previously allocated names on error
            for (int i = 0; i < *num_names; i++)
            {
                free(names[i]);
            }
            free(names);

            return NULL;
        }
        names = temp;

        // Store the new name in the names array
        names[*num_names] = new_name;
        (*num_names)++;
    }

    fclose(file);
    return names;
}

int compare_strings(const void *a, const void *b);
int compare_strings(const void *a, const void *b)
{
    const char *const *ptr1 = (const char *const *)a;
    const char *const *ptr2 = (const char *const *)b;
    const char *str1 = *ptr1;
    const char *str2 = *ptr2;
    return strcmp(str1, str2);
}

static void
extbuf_free_cb(void *addr __rte_unused, void *fcb_opaque __rte_unused)
{
}

static int
lcore_main(void *mbuf_pool)
{
    uint16_t port;
    struct rte_regex_ops **ops;
    // struct rte_regexdev_match *match;
    uint8_t nb_matches;
    struct rte_mbuf_ext_shared_info shinfo;
    shinfo.free_cb = extbuf_free_cb;

    ops = rte_malloc(NULL, sizeof(*ops), 0);
    if (!ops)
    {
        printf("Error, can't allocate memory for ops.\n");
    }
    ops[0] = rte_malloc(NULL, sizeof(*ops[0]) + sizeof(struct rte_regexdev_match), 0);
    if (!ops[0])
    {
        printf("Error, can't allocate "
               "memory for op.\n");
    }
    ops[0]->mbuf = rte_pktmbuf_alloc(mbuf_pool);

    char *dest_buf;
    dest_buf =
        rte_malloc(NULL, sizeof(char) * (MAX_SERVER_NAME), 4096);
    if (!dest_buf)
        return -ENOMEM;

    RTE_ETH_FOREACH_DEV(port)
    if (rte_eth_dev_socket_id(port) >= 0 &&
        rte_eth_dev_socket_id(port) !=
            (int)rte_socket_id())
        printf("WARNING, port %u is on remote NUMA node to "
               "polling thread.\n\tPerformance will "
               "not be optimal.\n",
               port);

    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
           rte_lcore_id());

    const char *filename = "/home/ubuntu/dpdk/examples/DNS_TLS/random_strings.txt";
    int num_names;
    char **names = read_names_from_file(filename, &num_names);
    qsort(names, num_names, sizeof(names[0]), compare_strings);

    uint16_t pkt_count = 0;
    // printf("ALi");
    for (;;)
    {
        // port=0;
        RTE_ETH_FOREACH_DEV(port)
        {
            struct rte_mbuf *bufs[BURST_SIZE];
            uint16_t nb_rx = rte_eth_rx_burst(port, 0,
                                              bufs, BURST_SIZE);

            // break;
            if (nb_rx > 0)
            {
                // printf("Ali \n");
                // uint64_t timestamp = rte_get_tsc_cycles();
                // uint64_t tsc_hz = rte_get_tsc_hz();
                // double timestamp_us = (double)timestamp / tsc_hz * 1e6;
                struct rte_ether_hdr *ethernet_header;
                struct rte_client_hello_dpdk_hdr *client_hello_dpdk;
                struct rte_server_hello_dpdk_hdr *server_hello_dpdk;    
                struct rte_ipv4_hdr *pIP4Hdr;
                struct rte_tcp_hdr *pTcpHdr;
                struct rte_tls_hdr *pTlsHdr;
                struct rte_tls_hdr *pTlsRecord1;
                struct rte_tls_hdr *pTlsRecord2;
                struct rte_tls_hello_hdr *pTlsHandshakeHdr;
                struct rte_tls_session_hdr *pTlsSessionHdr;
                struct rte_tls_cipher_hdr *pTlsChiperHdr;
                struct rte_tls_compression_hdr *pTlsCmpHdr;
                struct rte_tls_ext_len_hdr *pTlsExtLenHdr;
                struct rte_tls_ext_hdr *pTlsExtHdr;

                u_int16_t ethernet_type;
                for (int i = 0; i < nb_rx; i++)
                {
                    pkt_count +=1;
                    ethernet_header = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
                    ethernet_type = ethernet_header->ether_type;
                    ethernet_type = rte_cpu_to_be_16(ethernet_type);
                    // printf("The Ethernet type is %u\n",ethernet_type);
                    // if(pkt_count == 14){
                    //     exit(1);
                    // }

                    // if (ethernet_type == 2048)
                    if (ethernet_type == 2000) // Client Hello packet from the P4
                    {
                        ethernet_header->ether_type = rte_cpu_to_be_16(0x0700);

                        client_hello_dpdk = rte_pktmbuf_mtod_offset(bufs[i], struct rte_client_hello_dpdk_hdr *, sizeof(struct rte_ether_hdr));
                        client_hello_dpdk->type = 0x1;
                        uint32_t ipdata_offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_client_hello_dpdk_hdr);

                        // uint32_t ipdata_offset = sizeof(struct rte_ether_hdr);
                        pIP4Hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *, ipdata_offset);
                        uint8_t IPv4NextProtocol = pIP4Hdr->next_proto_id;
                        ipdata_offset += (pIP4Hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

                        if (IPv4NextProtocol == 6)
                        {

                            pTcpHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tcp_hdr *, ipdata_offset);
                            uint16_t dst_port = rte_be_to_cpu_16(pTcpHdr->dst_port);
                            uint16_t src_port = rte_be_to_cpu_16(pTcpHdr->src_port);
                            uint8_t tcp_dataoffset = pTcpHdr->data_off >> 4;
                            uint32_t tcpdata_offset = ipdata_offset + sizeof(struct rte_tcp_hdr) + (tcp_dataoffset - 5) * 4;
                            if (dst_port == 443 || src_port == 443)
                            {

                                pTlsHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_hdr *, tcpdata_offset);
                                uint8_t tls_type = pTlsHdr->type;
                                uint32_t tlsdata_offset = tcpdata_offset + sizeof(struct rte_tls_hdr);
                                if (tls_type == 0x16)
                                {
                                    pTlsHandshakeHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_hello_hdr *, tlsdata_offset);
                                    uint8_t handshake_type = pTlsHandshakeHdr->type;
                                    uint16_t temp_len = uint24_to_16(pTlsHandshakeHdr->len);
                                    client_hello_dpdk->len = rte_cpu_to_be_16(temp_len);
                                    tlsdata_offset += sizeof(struct rte_tls_hello_hdr);
                                    if (handshake_type == 1)
                                    {
                                        pTlsSessionHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_session_hdr *, tlsdata_offset);
                                        tlsdata_offset += (pTlsSessionHdr->len) + sizeof(struct rte_tls_session_hdr);

                                        pTlsChiperHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_cipher_hdr *, tlsdata_offset);
                                        uint16_t cipher_len = rte_cpu_to_be_16(pTlsChiperHdr->len);
                                        tlsdata_offset += cipher_len + sizeof(struct rte_tls_cipher_hdr);

                                        pTlsCmpHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_compression_hdr *, tlsdata_offset);
                                        tlsdata_offset += pTlsCmpHdr->len + sizeof(struct rte_tls_compression_hdr);

                                        pTlsExtLenHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_ext_len_hdr *, tlsdata_offset);
                                        uint16_t exts_len = rte_cpu_to_be_16(pTlsExtLenHdr->len);
                                        tlsdata_offset += sizeof(struct rte_tls_ext_len_hdr);

                                        bool blacklisted = false;

                                        uint16_t exts_nums = 0x0;
                                        while (exts_len > 0)
                                        {
                                            // printf("Ali\n");
                                            exts_nums +=1;
                                            pTlsExtHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_ext_hdr *, tlsdata_offset);
                                            uint16_t ext_type = rte_cpu_to_be_16(pTlsExtHdr->type);
                                            uint16_t ext_len = rte_cpu_to_be_16(pTlsExtHdr->len);
                                            tlsdata_offset += sizeof(struct rte_tls_ext_hdr);
                                            // if (ext_type == 0)
                                            // {
                                            //     if (ext_len == 0)
                                            //     {
                                            //         break;
                                            //     }
                                            //     uint32_t name_offset = tlsdata_offset + sizeof(struct rte_ctls_ext_sni_hdr);

                                            //     char *server_name = rte_pktmbuf_mtod_offset(bufs[i], char *, name_offset);
                                            //     int server_name_len = strlen(server_name);
                                            //     // rte_memcpy(dest_buf, server_name, server_name_len + 1);

                                            //     if (ops[0]->mbuf)
                                            //     {

                                            //         rte_pktmbuf_attach_extbuf(ops[0]->mbuf,
                                            //                                   server_name, 0, server_name_len, &shinfo);

                                            //         ops[0]->mbuf->data_len = server_name_len;
                                            //         ops[0]->mbuf->pkt_len = server_name_len;
                                            //     }
                                             
                                            //     else
                                            //     {
                                            //         printf("There is no space for ops[0]->mbuf");
                                            //     }
                                            //     ops[0]->user_id = i;
                                            //     ops[0]->group_id0 = 1;
                                            //     ops[0]->req_flags |= RTE_REGEX_OPS_REQ_STOP_ON_MATCH_F;

                                            //     uint32_t nb_enqueue =  rte_regexdev_enqueue_burst(0,
                                            //                                0,
                                            //                                ops,
                                            //                                1);

                                            //     uint32_t nb_dequeue = 0;
                                            //     while(nb_enqueue != nb_dequeue){
                                            //         nb_dequeue = rte_regexdev_dequeue_burst(0,
                                            //                                0,
                                            //                                ops,
                                            //                                1);
                                            //                                }

                                            //     nb_matches = ops[0]->nb_matches;
                                            //     if (nb_matches > 0)
                                            //     {
                                            //         // nb_rx--;
                                            //         // rte_pktmbuf_free(bufs[i]);
                                            //         // printf("Packet Blacklisted. Ethernet type is %u \n",ethernet_type);
                                            //         blacklisted = true;
                                            //         client_hello_dpdk->exts_num = rte_cpu_to_be_16(240);

                                            //     }
                                                
                                            // }
                                            // break;
                                            tlsdata_offset += ext_len;
                                            exts_len -= ext_len;
                                            exts_len -= sizeof(struct rte_tls_ext_hdr);
                                        }
                                        if(!blacklisted){
                                            client_hello_dpdk->exts_num = rte_cpu_to_be_16(exts_nums);
                                        }
                                        // client_hello_dpdk->exts_num = rte_cpu_to_be_16(2);
                                        // printf("Packet Client Hello %u has %u extensions and is %u bytes long\n",pkt_count, client_hello_dpdk->exts_num, client_hello_dpdk->len);
                                    }
                                }
                            }
                        }
                    }
                    else if (ethernet_type == 2001) // Server Hello packet from the P4
                    {
                        ethernet_header->ether_type = rte_cpu_to_be_16(0x0700);

                        server_hello_dpdk = rte_pktmbuf_mtod_offset(bufs[i], struct rte_server_hello_dpdk_hdr *, sizeof(struct rte_ether_hdr));
                        server_hello_dpdk->type = 2;
                        uint32_t ipdata_offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_server_hello_dpdk_hdr);

                        // uint32_t ipdata_offset = sizeof(struct rte_ether_hdr);
                        pIP4Hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *, ipdata_offset);
                        uint8_t IPv4NextProtocol = pIP4Hdr->next_proto_id;
                        ipdata_offset += (pIP4Hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

                        if (IPv4NextProtocol == 6)
                        {

                            pTcpHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tcp_hdr *, ipdata_offset);
                            uint16_t dst_port = rte_be_to_cpu_16(pTcpHdr->dst_port);
                            uint16_t src_port = rte_be_to_cpu_16(pTcpHdr->src_port);
                            uint8_t tcp_dataoffset = pTcpHdr->data_off >> 4;
                            uint32_t tcpdata_offset = ipdata_offset + sizeof(struct rte_tcp_hdr) + (tcp_dataoffset - 5) * 4;
                            if (dst_port == 443 || src_port == 443)
                            {

                                pTlsHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_hdr *, tcpdata_offset);
                                uint8_t tls_type = pTlsHdr->type;
                                uint32_t tlsdata_offset = tcpdata_offset + sizeof(struct rte_tls_hdr);
                                if (tls_type == 0x16)
                                {
                                    pTlsHandshakeHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_hello_hdr *, tlsdata_offset);
                                    uint8_t handshake_type = pTlsHandshakeHdr->type;
                                    uint16_t temp_len = uint24_to_16(pTlsHandshakeHdr->len);
                                    server_hello_dpdk->len = rte_cpu_to_be_16(temp_len);
                                    tlsdata_offset += sizeof(struct rte_tls_hello_hdr);
                                    if (handshake_type == 2)
                                    {
                                        pTlsSessionHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_session_hdr *, tlsdata_offset);
                                        tlsdata_offset += (pTlsSessionHdr->len) + sizeof(struct rte_tls_session_hdr);
                                        // printf("The session length is %u\n ",pTlsSessionHdr->len);

                                        tlsdata_offset +=  sizeof(struct rte_tls_cipher_hdr);

                                        tlsdata_offset += sizeof(struct rte_tls_compression_hdr);

                                        pTlsExtLenHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_ext_len_hdr *, tlsdata_offset);
                                        uint16_t exts_len = rte_cpu_to_be_16(pTlsExtLenHdr->len);
                                        // printf("The exts_len is %u\n ",exts_len);

                                        tlsdata_offset += sizeof(struct rte_tls_ext_len_hdr);

                                        uint16_t exts_nums = 0;
                                        while (exts_len >= 1)
                                        {
                                            exts_nums +=1;
                                            pTlsExtHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_ext_hdr *, tlsdata_offset);
                                            uint16_t ext_len = rte_cpu_to_be_16(pTlsExtHdr->len);
                                            tlsdata_offset += sizeof(struct rte_tls_ext_hdr);
                                            tlsdata_offset += ext_len;
                                            exts_len -= ext_len;
                                            exts_len -= sizeof(struct rte_tls_ext_hdr);
                                        }
                                        server_hello_dpdk->exts_num = rte_cpu_to_be_16(exts_nums);
                                        // nb_rx--;
                                        // rte_pktmbuf_free(bufs[i]);
                                        // printf("Packet Server Hello %u has %u extensions and is %u bytes long and dst port %u\n",
                                        // pkt_count, server_hello_dpdk->exts_num, server_hello_dpdk->len, dst_port);
                                    }
 
                                    pTlsRecord1 = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_hdr *, tlsdata_offset);
                                    tlsdata_offset += sizeof(struct rte_tls_hdr) + rte_be_to_cpu_16(pTlsRecord1->length);
                                    handshake_type = pTlsRecord1->type;

                                    server_hello_dpdk->version = rte_cpu_to_be_16(2);
                                    if(handshake_type == 0x16){
                                        server_hello_dpdk->version = rte_cpu_to_be_16(2);
                                    }
                                    else if(handshake_type == 0x14){
                                        pTlsRecord2 = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_hdr *, tlsdata_offset);
                                        handshake_type = pTlsRecord2->type;
                                        if(handshake_type == 0x17){
                                            server_hello_dpdk->version = rte_cpu_to_be_16(3);
                                        }
                                    }
                                    else if(handshake_type == 0x17){
                                        server_hello_dpdk->version = rte_cpu_to_be_16(3);
                                    }
                                }
                            }
                        }
                    }
                    // else {
                    //     nb_rx--;
                    //     rte_pktmbuf_free(bufs[i]);
                    // }
                }
                if (unlikely(nb_rx == 0))
                    continue;

                const uint16_t nb_tx = rte_eth_tx_burst(port, 0,
                                                        bufs, nb_rx);
                if (unlikely(nb_tx < nb_rx))
                {
                    printf("Ali\n");
                    uint16_t buf;

                    for (buf = nb_tx; buf < nb_rx; buf++)
                        rte_pktmbuf_free(bufs[buf]); 
                }

            }
        }
    }

    return 0;
}

static void close_ports(void);
static void close_ports(void)
{
    uint16_t portid;
    int ret;
    uint16_t nb_ports;
    nb_ports = rte_eth_dev_count_avail();
    for (portid = 0; portid < nb_ports; portid++)
    {
        printf("Closing port %d...", portid);
        ret = rte_eth_dev_stop(portid);
        if (ret != 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_stop: err=%s, port=%u\n",
                     strerror(-ret), portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }
}

/* Initialization of Environment Abstraction Layer (EAL). 8< */
int main(int argc, char **argv)
{
    struct rte_mempool *mbuf_pool;
    uint16_t nb_ports;
    uint16_t portid;
    unsigned lcore_id;
    int ret;

    // char rules_file[MAX_FILE_NAME] = "/home/ubuntu/rof/.rof2.binary";

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");

    argc -= ret;
    argv += ret;

    nb_ports = rte_eth_dev_count_avail();

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                                        NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    RTE_ETH_FOREACH_DEV(portid)
    if (port_init(portid, mbuf_pool) != 0)
    {
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
                 portid);
    }
    else{
        printf("port %u initialized\n",portid);
    }

    if (regex_init() != 0)
    {
        rte_exit(EXIT_FAILURE, "Cannot init regex device");
    }

    // struct rte_cryptodev_info dev_info;
    // rte_cryptodev_info_get(0, &dev_info);
    // uint8_t driver_id = dev_info.driver_id;
    // printf("The crypto driver name is %u\n",driver_id);

    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        rte_eal_remote_launch(lcore_main, mbuf_pool, lcore_id);
    }

    rte_eal_mp_wait_lcore();

    close_ports();

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}