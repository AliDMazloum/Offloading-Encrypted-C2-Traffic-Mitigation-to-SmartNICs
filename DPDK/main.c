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


static int
lcore_main(void *mbuf_pool)
{
    uint16_t port;

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
                printf("Ali \n");
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
    };

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