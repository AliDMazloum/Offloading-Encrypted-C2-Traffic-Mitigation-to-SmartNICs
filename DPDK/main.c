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

#include <rte_hash.h>
#include <rte_jhash.h>
#include <jansson.h>

#include <rte_flow.h>
#include <signal.h>

#define RX_RING_SIZE (1 << 15)
#define TX_RING_SIZE (1 << 15)

#define NUM_MBUFS (1 << 16)
// #define BURST_SIZE (1 << 9)

#define QUEUE_SIZE 128

#define BURST_SIZE 64

// #define QUEUE_SIZE (1 << 6)

#define MBUF_CACHE_SIZE 256

#define HASH_TABLE_SIZE (1 << 15) 

#define MAX_TREES 100
#define MAX_NODES 500

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

static void create_flow_rule(uint16_t port_id, uint16_t actions_to_be_taken);

/* >8 End of launching function on lcore. */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    uint16_t nb_queue_pairs = 1;
    uint16_t rx_rings = nb_queue_pairs, tx_rings = nb_queue_pairs;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    uint16_t rx_queue_size = QUEUE_SIZE;
    uint16_t tx_queue_size = QUEUE_SIZE;
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
        retval = rte_eth_rx_queue_setup(port, q, rx_queue_size,
                                        rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; q++)
    {
        retval = rte_eth_tx_queue_setup(port, q, tx_queue_size,
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


struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

struct flow_entry {
    uint16_t client_len;
    uint16_t exts_num;
};

typedef struct {
    int n_nodes;
    int left_child;
    int right_child;
    int feature;
    double threshold;
    int is_leaf;
    int class_label;
} TreeNode;

// Structure to hold random forest model
typedef struct {
    int n_estimators;
    int max_depth;
    double feature_importances[5];
    TreeNode trees[MAX_TREES][MAX_NODES];
} RandomForest;

// Function to read the JSON file and load the Random Forest model
int load_rf_model(const char *filename, RandomForest *rf) {
    json_error_t error;
    json_t *root = json_load_file(filename, 0, &error);

    if (!root) {
        fprintf(stderr, "Error loading JSON file: %s\n", error.text);
        return -1;
    }

    // Parse the general model parameters
    json_t *n_estimators = json_object_get(root, "n_estimators");
    json_t *max_depth = json_object_get(root, "max_depth");
    json_t *feature_importances = json_object_get(root, "feature_importances");

    rf->n_estimators = json_integer_value(n_estimators);
    rf->max_depth = json_integer_value(max_depth);

    // Parse feature importances
    for (int i = 0; i < 5; i++) {
        rf->feature_importances[i] = json_real_value(json_array_get(feature_importances, i));
    }

    // Parse each decision tree
    json_t *estimators = json_object_get(root, "estimators");
    size_t index;
    json_t *tree_data;

    json_array_foreach(estimators, index, tree_data) {
        TreeNode *tree = rf->trees[index];
        size_t n_nodes = json_integer_value(json_object_get(tree_data, "n_nodes"));

        // Parse the nodes of the tree
        json_t *children_left = json_object_get(tree_data, "children_left");
        json_t *children_right = json_object_get(tree_data, "children_right");
        json_t *feature = json_object_get(tree_data, "feature");
        json_t *threshold = json_object_get(tree_data, "threshold");
        json_t *class_label = json_object_get(tree_data, "class_label"); // Holds the class probabilities/counts
        json_t *leaves = json_object_get(tree_data, "leaves");

        for (int i = 0; i < n_nodes; i++) {
            TreeNode *node = &tree[i];
            node->feature = json_integer_value(json_array_get(feature, i));
            node->threshold = json_real_value(json_array_get(threshold, i));
            node->left_child = json_integer_value(json_array_get(children_left, i));
            node->right_child = json_integer_value(json_array_get(children_right, i));
            node->class_label = json_integer_value(json_array_get(class_label, i));
            node->is_leaf = json_integer_value(json_array_get(leaves, i));
        }
    }

    json_decref(root);
    return 0;
}

// Function to traverse a tree and make a prediction
int predict_tree(TreeNode *tree, double *sample, int node_index) {
    TreeNode *node = &tree[node_index];

    if (node->is_leaf) {
        return node->class_label;
    }

    if (sample[node->feature] <= node->threshold) {
        return predict_tree(tree, sample, node->left_child);
    } else {
        return predict_tree(tree, sample, node->right_child);
    }
}

// Function to make a prediction using the Random Forest
int predict(RandomForest *rf, double *sample) {
    int predictions[MAX_TREES];
    int final_prediction = 0;

    for (int i = 0; i < rf->n_estimators; i++) {
        predictions[i] = predict_tree(rf->trees[i], sample, 0);
    }

    // Majority voting for classification
    int count[3] = {0};  // Assuming 3 possible classes
    for (int i = 0; i < rf->n_estimators; i++) {
        count[predictions[i]]++;
    }

    // Find the majority vote
    for (int i = 0; i < 3; i++) {
        if (count[i] > count[final_prediction]) {
            final_prediction = i;
        }
    }

    return final_prediction;
}

// struct worker_args
// {
//     struct rte_mempool *mbuf_pool;
//     struct rte_hash *flow_table;
//     RandomForest *rf;
//     int packet_counters[10];
// };

struct
{
    struct rte_mempool *mbuf_pool;
    struct rte_hash *flow_table;
    RandomForest *rf;
    int packet_counters[10];
}worker_args;

double right_predictions=0;
double wrong_predictions=0;

double received_packets=0;
double processed_packets=0;

static int
lcore_main(void *args)
{
    // struct worker_args *w_args = (struct worker_args *)args;
    struct rte_mempool *mbuf_pool = worker_args.mbuf_pool;
    struct rte_hash *flow_table = worker_args.flow_table;
    RandomForest *rf = worker_args.rf;
    // int core_id = rte_lcore_id();
    // int *packet_counter = &worker_args.packet_counters[core_id];

    uint16_t port;
    uint16_t ret;

    struct flow_key key;
    struct flow_entry entry;

    double sample[5];

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


    uint32_t pkt_count = 0;
    uint16_t queue_id =  rte_lcore_id() - 1;


    for (;;)
    {
        // port=1;
        RTE_ETH_FOREACH_DEV(port)
        {
            struct rte_mbuf *bufs[BURST_SIZE];
            
            uint16_t nb_rx = rte_eth_rx_burst(port, queue_id,
                                              bufs, BURST_SIZE);

            // break;
            if (nb_rx > 0)
            {
                // *packet_counter +=nb_rx;
                // printf("Ali \n");
                // uint64_t timestamp = rte_get_tsc_cycles();
                // uint64_t tsc_hz = rte_get_tsc_hz();
                // double timestamp_us = (double)timestamp / tsc_hz * 1e6;
                received_packets+=nb_rx;
                struct rte_ether_hdr *ethernet_header; 
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
                    // pkt_count +=1;
                    ethernet_header = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
                    ethernet_type = ethernet_header->ether_type;
                    ethernet_type = rte_cpu_to_be_16(ethernet_type);

                    if (ethernet_type == 2048)
                    {
                        uint32_t ipdata_offset = sizeof(struct rte_ether_hdr);

                        pIP4Hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *, ipdata_offset);
                        uint32_t src_ip = rte_be_to_cpu_32(pIP4Hdr->src_addr);
                        uint32_t dst_ip = rte_be_to_cpu_32(pIP4Hdr->dst_addr);
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
                                        while (exts_len > 0 && tlsdata_offset < 1450)
                                        {
                                            exts_nums +=1;
                                            pTlsExtHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_ext_hdr *, tlsdata_offset);
                                            uint16_t ext_type = rte_cpu_to_be_16(pTlsExtHdr->type);
                                            uint16_t ext_len = rte_cpu_to_be_16(pTlsExtHdr->len);
                                            tlsdata_offset += sizeof(struct rte_tls_ext_hdr);
                                            tlsdata_offset += ext_len;
                                            exts_len -= ext_len;
                                            exts_len -= sizeof(struct rte_tls_ext_hdr);
                                        }

                                        key.src_ip = src_ip;  
                                        key.dst_ip = dst_ip; 
                                        key.src_port = src_port;
                                        key.dst_port = dst_port;
                                        key.protocol = IPv4NextProtocol;

                                        entry.client_len = temp_len;
                                        entry.exts_num = exts_nums;


                                        // ret = rte_hash_add_key_data(flow_table, &key, &entry);
                                        // if (ret < 0) {
                                        //     rte_panic("Failed to add flow entry\n");
                                        // }
                                        // else{
                                        //     // printf("Entry is added with len %u and exts_num %u\n",entry.client_len, entry.exts_num);
                                        // }

                                    }
                                    else if (handshake_type == 2)
                                    {
                                        pTlsSessionHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_session_hdr *, tlsdata_offset);
                                        tlsdata_offset += (pTlsSessionHdr->len) + sizeof(struct rte_tls_session_hdr);

                                        tlsdata_offset +=  sizeof(struct rte_tls_cipher_hdr);

                                        tlsdata_offset += sizeof(struct rte_tls_compression_hdr);

                                        pTlsExtLenHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_ext_len_hdr *, tlsdata_offset);
                                        uint16_t exts_len = rte_cpu_to_be_16(pTlsExtLenHdr->len);

                                        tlsdata_offset += sizeof(struct rte_tls_ext_len_hdr);

                                        uint16_t exts_nums = 0;
                                        while (exts_len >= 1 && tlsdata_offset < 1450)
                                        {
                                            exts_nums +=1;
                                            pTlsExtHdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tls_ext_hdr *, tlsdata_offset);
                                            uint16_t ext_len = rte_cpu_to_be_16(pTlsExtHdr->len);
                                            tlsdata_offset += sizeof(struct rte_tls_ext_hdr);
                                            tlsdata_offset += ext_len;
                                            exts_len -= ext_len;
                                            exts_len -= sizeof(struct rte_tls_ext_hdr);
                                        }
                                        key.src_ip = dst_ip;  
                                        key.dst_ip = src_ip; 
                                        key.src_port = dst_port;
                                        key.dst_port = src_port;
                                        key.protocol = IPv4NextProtocol;

                                        ret = rte_hash_lookup_data(flow_table, &key, (void **)&entry);
                                        if (ret < 0) {
                                            printf("Flow entry not found\n");
                                        } else {
                                            // printf("Flow entry found: %u client len, %u client exts_count, %u server len, %u server exts_count, \n"
                                            // , entry.client_len, entry.exts_num,temp_len,exts_nums);
                                            // rte_hash_del_key(flow_table, &key);

                                            sample[0] = entry.client_len;
                                            sample[1] = entry.exts_num;
                                            sample[2] = temp_len;
                                            sample[3] = exts_nums;
                                            sample[4] = 2;

                                            int prediction = predict(rf, sample);
                                            ret = rte_hash_del_key(flow_table, &key);
                                            if (ret < 0) {
                                                printf("Flow entry cannot be deleted\n");
                                            } 
                                            // create_flow_rule(0,prediction);
                                            // if(prediction !=0){
                                            //     printf("Predicted class: %d\n", prediction);
                                            // }

                                            // if(prediction == 1){
                                            //     right_predictions+=1;
                                            // }
                                            // else if(prediction == 0){
                                            //     wrong_predictions+=1;
                                            // }

                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if (unlikely(nb_rx == 0))
                    continue;

                const uint16_t nb_tx = rte_eth_tx_burst(port, queue_id,
                                                        bufs, nb_rx);

                processed_packets += nb_tx;

                if (unlikely(nb_tx < nb_rx))
                {
                    uint16_t buf;

                    // printf("SOme packets are not processed\n");

                    for (buf = nb_tx; buf < nb_rx; buf++)
                        rte_pktmbuf_free(bufs[buf]); 
                }

                // printf("Core %u proceesed %u packets\n",core_id,*packet_counter);

            }
        }
    }

    return 0;
}

static void
create_flow_rule(uint16_t port_id, uint16_t actions_to_be_taken)
{

    struct rte_flow *flow;
    struct rte_flow_attr flow_attr = {0};
    struct rte_flow_item pattern[2];
    struct rte_flow_item_ipv4 ip_spec = {0};
    struct rte_flow_item_ipv4 ip_mask = {0};
    struct rte_flow_action actions[2];
    struct rte_flow_action_queue queue = { .index = 0 };
    struct rte_flow_action_port_id port_id_config = {
        .id = 0,
    };

    struct rte_flow_action *action;

    memset(pattern, 0, sizeof(pattern));
    memset(actions, 0, sizeof(actions));

    /* Create the flow rule */
    struct rte_flow_error error;
    memset(&error,0,sizeof(error));

    /* Set up the flow action */
    memset(&flow_attr, 0, sizeof(struct rte_flow_attr));
    if(actions_to_be_taken == 0){
        
        /* Create flow pattern for IPv4 */
        memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
        memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
        ip_spec.hdr.dst_addr = 0;
        ip_mask.hdr.dst_addr = 0;
        ip_spec.hdr.src_addr = htonl(0);
        ip_mask.hdr.src_addr = 0;

        pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
        // pattern[0].spec = &ip_spec;
        // pattern[0].mask = &ip_mask;
        pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

        actions[0].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
        actions[0].conf = &port_id_config;
        actions[1].type = RTE_FLOW_ACTION_TYPE_END;
        flow_attr.transfer = 1;
        flow = rte_flow_create(0, &flow_attr, pattern, actions, &error);
        if (flow == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to create flow rule: %s\n", error.message);
        }
        else{
            printf("Flow with action %u is added on port %u\n", actions_to_be_taken, port_id);
        }
    }
    else if(actions_to_be_taken == 1){

        /* Create flow pattern for IPv4 */
        memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
        memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
        ip_spec.hdr.dst_addr = htonl(0);
        ip_mask.hdr.dst_addr = 0;
        ip_spec.hdr.src_addr = htonl(0);
        ip_mask.hdr.src_addr = 0;

        pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
        pattern[0].spec = &ip_spec;
        pattern[0].mask = &ip_mask;
        pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

        actions[0].type = RTE_FLOW_ACTION_TYPE_DROP;
        actions[0].conf = NULL;
        actions[1].type = RTE_FLOW_ACTION_TYPE_END;
        // flow_attr.ingress = 1;
        flow_attr.transfer = 1;
        flow = rte_flow_create(port_id, &flow_attr, pattern, actions, &error);
        if (flow == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to create flow rule: %s\n", error.message);
        }
        else{
            printf("Flow with action %u is added on port %u\n", actions_to_be_taken, port_id);
        }
    }
    else if(actions_to_be_taken == 2){

        struct rte_flow_item_ethdev ethdev_port;
        struct rte_flow_item_ethdev ethdev_mask;

        struct rte_flow_action_ethdev ethdev_port_action;


        memset(&ethdev_port, 0, sizeof(struct rte_flow_item_ethdev));
        memset(&ethdev_mask, 0, sizeof(struct rte_flow_item_ethdev));
        memset(&ethdev_port_action, 0, sizeof(struct rte_flow_action_ethdev));

        ethdev_port.port_id = 0;
        ethdev_mask.port_id = 0xffff;
        ethdev_port_action.port_id = 1;
        
        pattern[0].type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT;
        pattern[0].spec = &ethdev_port;
        pattern[0].mask = &ethdev_mask;
        pattern[0].last = NULL;
        pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

        // memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
        // memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
        // ip_spec.hdr.dst_addr = htonl(0);
        // ip_mask.hdr.dst_addr = 0;
        // ip_spec.hdr.src_addr = htonl(0);
        // ip_mask.hdr.src_addr = 0;

        // pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
        // pattern[0].spec = &ip_spec;
        // pattern[0].mask = &ip_mask;
        // pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

        // actions[0].type = RTE_FLOW_ACTION_TYPE_DROP;
        // actions[0].conf = NULL;
        actions[0].type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT;
        actions[0].conf = &ethdev_port_action;
        actions[1].type = RTE_FLOW_ACTION_TYPE_END;

        flow_attr.transfer = 1;
        
        flow = rte_flow_create(port_id, &flow_attr, pattern, actions, &error);
        if (flow == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to create flow rule: %s\n", error.message);
        }
        else{
            printf("Flow with action %u is added on port %u\n", actions_to_be_taken, port_id);
        }
        
    }
    else if(actions_to_be_taken == 3){

        /* Create flow pattern for IPv4 */
        memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
        memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
        ip_spec.hdr.dst_addr = htonl(0);
        ip_mask.hdr.dst_addr = 0;
        ip_spec.hdr.src_addr = htonl(0);
        ip_mask.hdr.src_addr = 0;

        pattern[0].type = RTE_FLOW_ITEM_TYPE_IPV4;
        pattern[0].spec = &ip_spec;
        pattern[0].mask = &ip_mask;
        pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

        actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
        actions[0].conf = &queue;
        actions[1].type = RTE_FLOW_ACTION_TYPE_END;

        flow_attr.ingress = 1;
        
        flow = rte_flow_create(1, &flow_attr, pattern, actions, &error);
        if (flow == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to create flow rule: %s\n", error.message);
        }
        else{
            printf("Flow with action %u is added on port %u\n", actions_to_be_taken, port_id);
        }
        
    }
    // actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	// actions[0].conf = &queue;



    // int res = rte_flow_validate(port_id, &flow_attr, pattern, actions, &error);
    // if(!res)
    //     printf("error\n");
    //     // flow = rte_flow_create(port_id, &flow_attr, pattern, action, NULL);
    // else
    //     rte_exit(EXIT_FAILURE, "Failed to create flow rule\n");
    
    // flo<w = rte_flow_create(port_id, &flow_attr, pattern, actions, NULL);
    // if (flow == NULL) {
    //     rte_exit(EXIT_FAILURE, "Failed to create flow rule\n");
    // }>


    // printf("Flow rule created successfully\n");
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
    // int packet_counters[10] = {0};

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");


    struct rte_hash *flow_table;
    struct rte_hash_parameters hash_params = {0};

    hash_params.name = "flow_table";
    hash_params.entries = HASH_TABLE_SIZE;
    hash_params.key_len = sizeof(struct flow_key);
    hash_params.hash_func = rte_jhash;
    hash_params.hash_func_init_val = 0;
    hash_params.socket_id = rte_socket_id();

    flow_table = rte_hash_create(&hash_params);
    if (!flow_table) {
        rte_panic("Failed to create hash table\n");
    }

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

    // create_flow_rule(1,0);
    
    RandomForest rf;

    // Load the model from the JSON file
    if (load_rf_model("../rf_model.json", &rf) != 0) {
        return -1;
    }

    // struct worker_args arguments = {
    //     .mbuf_pool = mbuf_pool,
    //     .flow_table = flow_table,
    //     .rf = &rf,
    //     // .packet_counters = packet_counters[0]
    // };
    worker_args.mbuf_pool = mbuf_pool;
    worker_args.flow_table = flow_table;
    worker_args.rf = &rf;

    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        rte_eal_remote_launch(lcore_main, &worker_args, lcore_id);
    }

    char command[50];

    int *packet_counters = worker_args.packet_counters;


    while (1) {
        printf("Enter command: ");
        scanf("%s", command);
        // printf("The input command is %s\n",command);

        if (strcmp(command, "get_stats") == 0) {
            RTE_LCORE_FOREACH_WORKER(lcore_id)
            {

                char output_file[50]; //= "../datasets/DoHBrw/predictions.txt";
                
                printf("Enter file name: ");
                scanf("%s", output_file);   

                FILE *file = fopen(output_file, "w");

                if (file == NULL) {
                    printf("Error opening the file.\n");
                    return -1;
                }

                fprintf(file, "Received Processed Dropped\n");
                // printf("Core %u processed %u packets\n",lcore_id,packet_counters[lcore_id]);
                fprintf(file, "%f %f %.3f \n",received_packets,processed_packets,(double)(processed_packets/received_packets));
                right_predictions = 0;
                wrong_predictions = 0;
                received_packets = 0;
                processed_packets = 0;

                fclose(file);
                // packet_counters[lcore_id] = 0;
            }
            // break;
        }
    }


    rte_eal_mp_wait_lcore();

    rte_hash_free(flow_table);

    close_ports();

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}