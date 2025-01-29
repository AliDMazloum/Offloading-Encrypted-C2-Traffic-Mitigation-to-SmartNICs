/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

typedef bit<8> ip_protocol_t;

const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> TYPE_DPDK = 0x0700;
const bit<16> TYPE_RECIRC = 0x88B5;
const bit<8> TYPE_DPDK_PASS = 0x3;
const bit<8> TYPE_DPDK_CLIENT = 0x1;
const bit<8> TYPE_DPDK_Server = 0x2;



const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

#define COMPRESSION_STATE 0x1
#define EXTENSION_STATE 0x1
#define SESSION_LEN 0x1
#define COMP_LEN 0x1
#define CIPHER_LIM 0x1
#define EXT_LIM 0x2
#define SNI_LEN 0x3

#define  MAX_REGISTER_ENTRIES 32767
#define INDEX_WIDTH 16

#define PARSING_STALLED 0x1

typedef bit<8>  pkt_type_t;

#if __TARGET_TOFINO__ == 1
typedef bit<3> mirror_type_t;
#else
typedef bit<4> mirror_type_t;
#endif
const mirror_type_t MIRROR_TYPE_I2E = 1;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

header mirror_bridged_metadata_h {
    pkt_type_t pkt_type;
    @flexible bit<1> do_egr_mirroring;  //  Enable egress mirroring
    @flexible MirrorId_t egr_mir_ses;   // Egress mirror session ID
}

header mirror_h {
    pkt_type_t  mirror_type;   
}

header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header dpdk_h {
    bit<8> type;
}

header client_hello_dpdk_h {
    bit<16> len;
    bit<16> exts_num;
}

header server_hello_dpdk_h {
    bit<16> len;
    bit<16> exts_num;
    bit<16> version;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header tcp_ports_h{
    // bit<32> ports;
    bit<16> src_port;
    bit<16> dst_port;
}

header tcp_h {
    // bit<16> src_port;
    // bit<16> dst_port;
    // bit<32> ports;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header fixed_options_h {
    bit<96> options;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

header tls_h { 
    bit<8> type;
    bit<16> version;
    bit<16> len;
}

header tls_handshake_h {
	bit<8> type;
}

header tls_client_hello_h {
    bit<24> len;
    bit<16> version;
    bit<256> random;
}

header tls_server_hello_h {
    bit<24> len;
    bit<16> version;
}

header tls_session_h {
    bit<8> len;
}

header tls_cipher_h {
    bit<16> len;
    // In Client: ciphers follow
}
header tls_compression_h {
    bit<8> len;
    //  In Client: compressions follow
}
header tls_exts_len_h {
    bit<16> len;
}
header tls_ext_h {
    bit<16> type;
    bit<16> len;
}
header ctls_ext_sni_h {
    bit<16> sni_list_len;
    bit<8> type;
    bit<16> sni_len;
}
header hostname_part1 {
    bit<8> part;
}
header hostname_part2 {
    bit<16> part;
}
header hostname_part4 {
    bit<32> part;
}
header hostname_part8 {
    bit<64> part;
}
header hostname_part16 {
    bit<128> part;
}
header hostname_part32 {
    bit<256> part;
}

header tls_continue_h { 
    bit<16> id;
}

header unparsed_part_t {
    bit<8> unparsed;
}

header recirc_h {
    bit<8>       class_result;
}

header features_h {
    bit<16> client_hello_len;
    bit<16> client_hello_exts_number;
    bit<16> server_hello_len;
    bit<16> server_hello_exts_number;
    bit<16> tls_version; 
}

struct flow_class_digest {  // maximum size allowed is 47 bytes
    bit<INDEX_WIDTH> flow_ID;
    bit<INDEX_WIDTH> rev_flow_ID;
    bit<32> src_addr;
    bit<32> dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> client_hello_len;
    bit<16> client_hello_exts_number;
    bit<16> server_hello_len;
    bit<16> server_hello_exts_number;
    bit<16> tls_version; 
    bit<8> class_value;
}

struct client_hello_digest {  // maximum size allowed is 47 bytes
    bit<INDEX_WIDTH> flow_ID;
    bit<32> src_addr;
    bit<32> dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> client_hello_len;
    bit<16> client_hello_exts_number;
}

/***********************  I N G R E S S  H E A D E R S  ************************/
struct my_ingress_headers_t {
    ethernet_h   ethernet;
    recirc_h     recirc;

    dpdk_h       dpdk;
    client_hello_dpdk_h client_hello_dpdk;
    server_hello_dpdk_h server_hello_dpdk;
    features_h features;

    ipv4_h       ipv4;
    udp_h        udp;

    tcp_ports_h  tcp_ports;
    tcp_h        tcp;
    unparsed_part_t unparsed_part;
    tls_h        tls;

    tls_handshake_h tls_handshake;
    
    // TLS Cleint Hello
    tls_client_hello_h tls_client_hello;

    // TLS Server Hello
    tls_server_hello_h tls_server_hello;

    // Client Hello
    tls_session_h hello_session;
    tls_cipher_h hello_ciphers;
    tls_compression_h compressions;
    tls_exts_len_h extensions_len;
    tls_ext_h extensions;
    tls_ext_h extension;
    tls_ext_h extension_long;
    tls_ext_h extension_long_1;
    ctls_ext_sni_h client_servername;
    hostname_part1 servername_part1;
    hostname_part2 servername_part2;
    hostname_part4 servername_part4;
    hostname_part8 servername_part8;
    hostname_part16 servername_part16;
    hostname_part32 servername_part32;

}

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
struct my_ingress_metadata_t {
    bit<INDEX_WIDTH> flow_ID;
    bit<INDEX_WIDTH> rev_flow_ID;
    bit<8> final_class;
    bit<8> unparsed;
    MirrorId_t ing_mir_ses;   // Ingress mirror session ID
    pkt_type_t pkt_type;
}

/***********************  E G R E S S  H E A D E R S  ***************************/

struct my_egress_headers_t {
    // mirror_bridged_metadata_h bridged_md;
    mirror_h mirror_md;
    ethernet_h ethernet;
    dpdk_h dpdk;
    client_hello_dpdk_h client_hello_dpdk;
    server_hello_dpdk_h server_hello_dpdk;
    recirc_h     recirc;
    features_h features; // This one is equal to tls_server_hello_h + tls_client_hello_h
	ipv4_h ipv4;
}

/********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {

    bit<8> pkt_type;

    bit<8> class0;
    bit<8> class1;
    bit<8> class2;
    bit<8> class3;
    bit<8> class4;
    
    bit<8> final_class;

    bit<8> codeword0;
    bit<12> codeword1;
    bit<9> codeword2;
    bit<8> codeword3;
    bit<9> codeword4;
}
