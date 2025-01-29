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
#include <stdlib.h>
#include <inttypes.h>
#include <getopt.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>
#include <signal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_regexdev.h>
#include <rte_hexdump.h>
#include <rte_timer.h>

#include <rte_crypto.h>
#include <rte_cryptodev.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 16384
#define BURST_SIZE 1024

#define MAX_FILE_NAME 255
#define MBUF_CACHE_SIZE 256

#define min(a, b) ((a) < (b) ? (a) : (b))

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
    uint16_t nb_queue_pairs = 7;
    uint16_t rx_rings = nb_queue_pairs, tx_rings = nb_queue_pairs;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxconf;
    struct rte_eth_txconf txconf;
    struct rte_eth_conf port_conf = {
        .rxmode = {
		    .mq_mode = RTE_ETH_MQ_RX_RSS,
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = NULL,
                .rss_hf = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_TCP,
            },
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
    };

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

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
    uint16_t nb_queue_pairs = 7;
    struct rte_regexdev_info info;
    struct rte_regexdev_config dev_conf = {
        .nb_queue_pairs = nb_queue_pairs,
        .nb_groups = 1,
    };
    struct rte_regexdev_qp_conf qp_conf = {
        .nb_desc = 1024,
        .qp_conf_flags = 0,
    };
    char rules_file[MAX_FILE_NAME] = "/home/ubuntu/rof/.rof2.binary"; // rxpc -f rules.txt -o /home/ubuntu/rof/

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
        dev_conf.nb_queue_pairs = nb_queue_pairs;
        retval = rte_regexdev_configure(id, &dev_conf);
        if (retval < 0)
        {
            printf("Error, can't configure device %d.\n", id);
            goto error;
        }
        if (info.regexdev_capa & RTE_REGEXDEV_CAPA_QUEUE_PAIR_OOS_F)
            qp_conf.qp_conf_flags |=
                RTE_REGEX_QUEUE_PAIR_CFG_OOS_F;
        for (qp_id = 0; qp_id < nb_queue_pairs; qp_id++)
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


static int
lcore_main(void *mbuf_pool)
{
    uint16_t port;
    struct rte_regex_ops **ops;
    uint8_t nb_matches; 

    ops = rte_malloc(NULL, sizeof(*ops)*BURST_SIZE, 0);
    if (!ops)
    {
        printf("Error, can't allocate memory for ops.\n");
    }
    for(int i = 0;i<BURST_SIZE;i++){
        // ops[i] = rte_malloc(NULL, sizeof(*ops[i]) + sizeof(struct rte_regexdev_match), 0);
        ops[i] = rte_malloc(NULL, sizeof(struct rte_regex_ops) + sizeof(struct rte_regexdev_match), 0);
        if (!ops[i])
        {
            printf("Error, can't allocate "
                "memory for op[%i].\n",i);
        }
        ops[i]->mbuf = rte_pktmbuf_alloc(mbuf_pool);

    }

    RTE_ETH_FOREACH_DEV(port)
    if (rte_eth_dev_socket_id(port) >= 0 &&
        rte_eth_dev_socket_id(port) !=
            (int)rte_socket_id())
        printf("WARNING, port %u is on remote NUMA node to "
               "polling thread.\n\tPerformance will "
               "not be optimal.\n",
               port);

    printf("\nCore %u forwarding packets and connected to rx queues %u of the enabled ports.\n",rte_lcore_id(),rte_lcore_id() - 1);

    uint16_t queue_id =  rte_lcore_id() - 1;
    uint16_t regex_queue_id =  rte_lcore_id() - 1;

    while (1)
    {
        RTE_ETH_FOREACH_DEV(port)
        {
            struct rte_mbuf *bufs[BURST_SIZE];
            uint16_t nb_rx = rte_eth_rx_burst(port, queue_id,
                                              bufs, BURST_SIZE);

            if (nb_rx > 0)
            {
                for (int i = 0; i < nb_rx; i++)
                {
                    // printf("Packet hash is %u\n",bufs[i]->hash.rss);
                    struct rte_ipv4_hdr *ip_hdr;
                    uint16_t ipdata_offset;

                    ipdata_offset = sizeof(struct rte_ether_hdr);
                    ip_hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *,ipdata_offset);
                    ipdata_offset += (ip_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK)* RTE_IPV4_IHL_MULTIPLIER;

                    ops[i]->mbuf = bufs[i];
                    ops[i]->user_id = rte_lcore_id();
                    ops[i]->group_id0 = 1;
                    ops[i]->req_flags |= RTE_REGEX_OPS_REQ_STOP_ON_MATCH_F;

                }

                uint32_t nb_enqueue =  rte_regexdev_enqueue_burst(0,
                                            regex_queue_id,
                                            ops,
                                            nb_rx);
                
                uint32_t total_dequeue = 0;
                
                do{
                    uint32_t nb_dequeue = rte_regexdev_dequeue_burst(0,
                                            regex_queue_id,
                                            ops,
                                            nb_enqueue);

                    total_dequeue += nb_dequeue;
                    for (uint32_t i = 0; i < nb_dequeue; i++) {
                        nb_matches = ops[i]->nb_matches;
                        if (nb_matches > 0)
                        {
                            // Action to be taken if there is a match
                            // printf("Match detected on rule %u \n",ops[i]->matches->rule_id);
                            //drop the packet:
                                // rte_pktmbuf_free(bufs[i]);
                                // nb_rx--;
                        }

                    }
                } while((nb_enqueue > 0) && (total_dequeue < nb_enqueue));

                if (unlikely(nb_rx == 0))
                    continue;

                const uint16_t nb_tx = rte_eth_tx_burst(port, queue_id,
                                                        bufs, nb_rx);
                if (unlikely(nb_tx < nb_rx))
                {
                    printf("Cannot process all packets. %u are recieved on queue %u of port %u, core %u.\
 %u are transmitted back\n",nb_rx,queue_id,port,rte_lcore_id(),nb_tx);
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

    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        rte_eal_remote_launch(lcore_main, mbuf_pool, lcore_id);
    }

    rte_eal_mp_wait_lcore();

    close_ports();

    rte_eal_cleanup();

    return 0;
}