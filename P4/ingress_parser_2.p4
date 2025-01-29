
/***********************  P A R S E R  **************************/

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            TYPE_DPDK : parse_dpdk_packet;
            TYPE_RECIRC : parse_recirc;
            default: accept;
        }
    }

    state parse_recirc {
       pkt.extract(hdr.recirc);
       transition parse_features;
    }

    state parse_features {
        pkt.extract(hdr.features);
        transition parse_ipv4_dpdk;
    }

    state parse_dpdk_packet {
       pkt.extract(hdr.dpdk);
       transition select(hdr.dpdk.type) {
            TYPE_DPDK_PASS:  accept;
            TYPE_DPDK_CLIENT : parse_dpdk_client;
            TYPE_DPDK_Server : parse_dpdk_server;
            default: accept;
        }
    }

    state parse_dpdk_client {
       pkt.extract(hdr.client_hello_dpdk);
       transition parse_ipv4_dpdk;
    }

    state parse_dpdk_server {
       pkt.extract(hdr.server_hello_dpdk);
       transition parse_ipv4_dpdk;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp_ports;
            default : accept;
        }
    }

    state parse_ipv4_dpdk {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp_ports_dpdk;
            default : accept;
        }
    }

    // state parse_tcp_ports {
    //     pkt.extract(hdr.tcp_ports);
    //     transition select(hdr.tcp_ports.ports) {
    //         0x01BB0000 &&& 0xFFFF0000: parse_tcp;
    //         0x000001BB &&& 0x0000FFFF: parse_tcp;
    //         // 443: parse_tls;
    //         default: accept;
    //     }
    // }

    state parse_tcp_ports_dpdk {
        pkt.extract(hdr.tcp_ports);
        transition accept;
    }

    state parse_tcp_ports {
        pkt.extract(hdr.tcp_ports);
        transition select(hdr.tcp_ports.dst_port) {
            443: parse_tcp;
            default: parse_returning_traffic;
        }
    }

    state parse_returning_traffic {
        transition select(hdr.tcp_ports.src_port) {
            443: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.data_offset) {
            0x05 : parse_tls;
            0x08 : parse_tcp_options_08; 
            default: accept;
        }
    }

    state parse_tcp_options_08 {pkt.advance(96);transition parse_tls;}

    state parse_tls {
        pkt.extract(hdr.tls);
		transition select(hdr.tls.type){
			22: parse_tls_handshake;
			default: accept;
		}
    }

    state parse_tls_handshake {
		pkt.extract(hdr.tls_handshake);
		transition select(hdr.tls_handshake.type){
			1: parse_tls_client_hello;
			2: parse_tls_server_hello;
			default: accept;
		}
	}

    state parse_tls_client_hello {
        // pkt.extract(hdr.tls_server_hello);
        pkt.extract(hdr.tls_client_hello);
        transition parse_session_ids;
        // transition accept;
    }

    state parse_tls_server_hello {
        pkt.extract(hdr.tls_server_hello);
        transition accept;
    }

    state parse_session_ids {
        pkt.extract(hdr.hello_session);
        transition select(hdr.hello_session.len[7:4]) {
            0x00: skip_session_len_16_0;
            0x01: skip_session_len_16_1;
            0x02: skip_session_len_32_1;
            0x03: skip_session_len_48_1;
            default: unparsed_session;
        }
    }

    state unparsed_session {
        meta.unparsed = SESSION_LEN;
        transition accept;
    }

    state skip_session_len_16_0 {
        transition select(hdr.hello_session.len[3:3]) {
            0x00: skip_session_len_8_0;
            0x01: skip_session_len_8_1;
        }
    }

    state skip_session_len_8_1 {pkt.advance(64);transition skip_session_len_8_0;}
    state skip_session_len_16_1 {pkt.advance(128);transition skip_session_len_16_0;}
    state skip_session_len_32_1 {pkt.advance(256);transition skip_session_len_16_0;}
    state skip_session_len_48_1 {pkt.advance(384);transition skip_session_len_16_0;}

    state skip_session_len_8_0 {
        transition select(hdr.hello_session.len[2:0]) {
            0x00: hello_cipher;
            0x01: skip_session_len_1;
            0x02: skip_session_len_2;
            0x03: skip_session_len_3;
            0x04: skip_session_len_4;
            0x05: skip_session_len_5;
            0x06: skip_session_len_6;
            0x07: skip_session_len_7;
        }
    }

    state skip_session_len_1 {pkt.advance(08); transition hello_cipher;}
    state skip_session_len_2 {pkt.advance(16); transition hello_cipher;}
    state skip_session_len_3 {pkt.advance(24); transition hello_cipher;}
    state skip_session_len_4 {pkt.advance(32); transition hello_cipher;}
    state skip_session_len_5 {pkt.advance(40); transition hello_cipher;}
    state skip_session_len_6 {pkt.advance(48); transition hello_cipher;}
    state skip_session_len_7 {pkt.advance(56); transition hello_cipher;}


    state hello_cipher {
        pkt.extract(hdr.hello_ciphers);
        transition select(hdr.hello_ciphers.len[13:4]) {
            0x00: parse_cipher_len_16_0;
            0x01: parse_cipher_len_16_1;
            0x02: parse_cipher_len_32_1;
            0x03: parse_cipher_len_48_1;
            0x04: parse_cipher_len_64_1;
            default: unparsed_cipher;
        }
    }

    state unparsed_cipher {meta.unparsed = CIPHER_LIM;transition accept;}

    state parse_cipher_len_16_0 {
        transition select(hdr.hello_ciphers.len[3:1]) {
            0x00: parse_compressions;
            0x01: parse_cipher_len_1;
            0x02: parse_cipher_len_2;
            0x03: parse_cipher_len_3;
            0x04: parse_cipher_len_4;
            0x05: parse_cipher_len_5;
            0x06: parse_cipher_len_6;
            0x07: parse_cipher_len_7;
        }
    }

    state parse_cipher_len_16_1 {pkt.advance(128);transition parse_cipher_len_16_0;}
    state parse_cipher_len_32_1 {pkt.advance(256);transition parse_cipher_len_16_0;}
    state parse_cipher_len_48_1 {pkt.advance(384);transition parse_cipher_len_16_0;}
    state parse_cipher_len_64_1 {pkt.advance(512);transition parse_cipher_len_16_0;}

    state parse_cipher_len_1 {pkt.advance(016); transition parse_compressions;}
    state parse_cipher_len_2 {pkt.advance(032); transition parse_compressions;}
    state parse_cipher_len_3 {pkt.advance(048); transition parse_compressions;}
    state parse_cipher_len_4 {pkt.advance(064); transition parse_compressions;}
    state parse_cipher_len_5 {pkt.advance(080); transition parse_compressions;}
    state parse_cipher_len_6 {pkt.advance(096); transition parse_compressions;}
    state parse_cipher_len_7 {pkt.advance(112); transition parse_compressions;}

    state parse_compressions {
        bit<8> compressions = pkt.lookahead<bit<8>>();
        transition select (compressions) {
            0x01: parse_compressions_len_1;
            default: unparsed_compression;
        }
    }
    state unparsed_compression {
        meta.unparsed = COMP_LEN;
        transition accept;
    }
    state parse_compressions_len_1 {
        pkt.advance(16);
        transition parse_extensions_len;
    }

    state parse_extensions_len {
        bit<16> extensions_len = pkt.lookahead<bit<16>>();
        transition select(extensions_len) {
            0x0000: accept;
            default: skip_extensions_len;
        }
    }

    /////////////////////////////////////////////////////////////////////////////
    //////////////////////////  Extension Parsing Start ////////////////////////
    ///////////////////////////////////////////////////////////////////////////

    state skip_extensions_len {
        pkt.advance(16);
        transition parse_extension;
    }

    state parse_extension {
        bit<32> extension = pkt.lookahead<bit<32>>();
        transition select(extension[31:16]) {
            0x00: parse_server_name;
            default: skip_extension;
        }
    }

    state unparsed_extension {
        meta.unparsed = EXT_LIM;
        transition accept;
    }


    state skip_extension {
        bit<32> extension = pkt.lookahead<bit<32>>();
        transition select(extension[15:0]) {
            0x00: skip_extension_len_0; 
            0x01: skip_extension_len_1;
            0x02: skip_extension_len_2;
            0x03: skip_extension_len_3;
            0x04: skip_extension_len_4;
            0x05: skip_extension_len_5;
            0x06: skip_extension_len_6;
            0x07: skip_extension_len_7;
            0x08: skip_extension_len_8;
            0x09: skip_extension_len_9;
            0x0a: skip_extension_len_10;
            0x0b: skip_extension_len_11;
            0x0c: skip_extension_len_12;
            0x0d: skip_extension_len_13;
            0x0e: skip_extension_len_14;
            0x0f: skip_extension_len_15;
            0x10: skip_extension_len_16;
            0x11: skip_extension_len_17;
            0x12: skip_extension_len_18;
            0x13: skip_extension_len_19;
            0x14: skip_extension_len_20;
            0x15: skip_extension_len_21;
            0x16: skip_extension_len_22;
            0x17: skip_extension_len_23;
            0x18: skip_extension_len_24;
            0x19: skip_extension_len_25;
            0x1a: skip_extension_len_26;
            0x1b: skip_extension_len_27;
            0x1c: skip_extension_len_28;
            0x1d: skip_extension_len_29;
            0x1e: skip_extension_len_30;
            0x20: skip_extension_len_31;
            default: parse_extension_long; 
        }
    }

    state skip_extension_len_0 {pkt.advance(32); transition parse_extension; }
    state skip_extension_len_1 {pkt.advance(40); transition parse_extension; }
    state skip_extension_len_2 {pkt.advance(48); transition parse_extension; }
    state skip_extension_len_3 {pkt.advance(56); transition parse_extension; }
    state skip_extension_len_4 {pkt.advance(64); transition parse_extension; }
    state skip_extension_len_5 {pkt.advance(72); transition parse_extension; }
    state skip_extension_len_6 {pkt.advance(80); transition parse_extension; }
    state skip_extension_len_7 {pkt.advance(88); transition parse_extension; }
    state skip_extension_len_8 {pkt.advance(96); transition parse_extension; }
    state skip_extension_len_9 {pkt.advance(104); transition parse_extension;}

    state skip_extension_len_10 {pkt.advance(112); transition parse_extension;}
    state skip_extension_len_11 {pkt.advance(120); transition parse_extension;}
    state skip_extension_len_12 {pkt.advance(128); transition parse_extension;}
    state skip_extension_len_13 {pkt.advance(136); transition parse_extension;}
    state skip_extension_len_14 {pkt.advance(144); transition parse_extension;}
    state skip_extension_len_15 {pkt.advance(152); transition parse_extension;}
    state skip_extension_len_16 {pkt.advance(160); transition parse_extension;}
    state skip_extension_len_17 {pkt.advance(168); transition parse_extension;}
    state skip_extension_len_18 {pkt.advance(176); transition parse_extension;}
    state skip_extension_len_19 {pkt.advance(184); transition parse_extension;}
    state skip_extension_len_20 {pkt.advance(192); transition parse_extension;}
    state skip_extension_len_21 {pkt.advance(200); transition parse_extension;}
    state skip_extension_len_22 {pkt.advance(208); transition parse_extension;}
    state skip_extension_len_23 {pkt.advance(216); transition parse_extension;}
    state skip_extension_len_24 {pkt.advance(224); transition parse_extension;}
    state skip_extension_len_25 {pkt.advance(232); transition parse_extension;}
    state skip_extension_len_26 {pkt.advance(240); transition parse_extension;}

    state skip_extension_len_27 {pkt.advance(216); transition skip_extension_len_0;}
    state skip_extension_len_28 {pkt.advance(216); transition skip_extension_len_1;}
    state skip_extension_len_29 {pkt.advance(216); transition skip_extension_len_2;}
    state skip_extension_len_30 {pkt.advance(216); transition skip_extension_len_3;}
    state skip_extension_len_31 {pkt.advance(216); transition skip_extension_len_4;}
    
    /////////////////////////////////////////////////////////////////////////////
    ///////////////////////////  Extension long start //////////////////////////
    ///////////////////////////////////////////////////////////////////////////

    state parse_extension_long {
        // transition unparsed_extension;
        pkt.extract(hdr.extension_long);
        transition select(hdr.extension_long.len[10:5]) {
            0x01: skip_extension_long_len_32;
            0x02: skip_extension_long_len_64;
            0x03: skip_extension_long_len_96;
            0x04: skip_extension_long_len_128;
            0x05: skip_extension_long_len_160;
            0x06: skip_extension_long_len_192;
            0x07: skip_extension_long_len_224;
            0x08: skip_extension_long_len_256;
            default: unparsed_extension;
        }
    }

    state skip_extension_long_stage_2_0 {
        transition select(hdr.extension_long.len[4:3]) {
            0x00: skip_extension_long_len_8_0; 
            0x01: skip_extension_long_len_8;
            0x02: skip_extension_long_len_16;
            0x03: skip_extension_long_len_24;
        }
    }

    state skip_extension_long_len_8_0 {
        transition select(hdr.extension_long.len[2:0]) {
            0x00: parse_extension_stage_2;
            0x01: skip_extension_long_len_1;
            0x02: skip_extension_long_len_2;
            0x03: skip_extension_long_len_3;
            0x04: skip_extension_long_len_4;
            0x05: skip_extension_long_len_5;
            0x06: skip_extension_long_len_6;
            0x07: skip_extension_long_len_7;
        }
    }

    state skip_extension_long_len_1  {pkt.advance(08); transition parse_extension_stage_2; }
    state skip_extension_long_len_2  {pkt.advance(16); transition parse_extension_stage_2; }
    state skip_extension_long_len_3  {pkt.advance(24); transition parse_extension_stage_2; }
    state skip_extension_long_len_4  {pkt.advance(32); transition parse_extension_stage_2; }
    state skip_extension_long_len_5  {pkt.advance(40); transition parse_extension_stage_2; }
    state skip_extension_long_len_6  {pkt.advance(48); transition parse_extension_stage_2; }
    state skip_extension_long_len_7  {pkt.advance(56); transition parse_extension_stage_2; }
    
    state skip_extension_long_len_8  {pkt.advance(64); transition skip_extension_long_len_8_0;}
    state skip_extension_long_len_16 {pkt.advance(128);transition skip_extension_long_len_8_0;}
    state skip_extension_long_len_24 {pkt.advance(192);transition skip_extension_long_len_8_0;}

    state skip_extension_long_len_32 {pkt.advance(256);transition skip_extension_long_stage_2_0;} 
    state skip_extension_long_len_64 {pkt.advance(512);transition skip_extension_long_stage_2_0;}
    state skip_extension_long_len_96 {pkt.advance(768);transition skip_extension_long_stage_2_0;}
    state skip_extension_long_len_128 {pkt.advance(1024);transition skip_extension_long_stage_2_0;}
    state skip_extension_long_len_160 {pkt.advance(1280);transition skip_extension_long_stage_2_0;}
    state skip_extension_long_len_192 {pkt.advance(1536);transition skip_extension_long_stage_2_0;}
    state skip_extension_long_len_224 {pkt.advance(1792);transition skip_extension_long_stage_2_0;}
    state skip_extension_long_len_256 {pkt.advance(2048);transition skip_extension_long_stage_2_0;}

    /////////////////////////////////////////////////////////////////////////////
    ////////////////////////////  Extension long end ///////////////////////////
    ///////////////////////////////////////////////////////////////////////////

    
    /////////////////////////////////////////////////////////////////////////////
    /////////////////////////  Extension stage 2 start /////////////////////////
    ///////////////////////////////////////////////////////////////////////////

    state parse_extension_stage_2 {
        // transition unparsed_extension;
        bit<32> extension = pkt.lookahead<bit<32>>();
        transition select(extension[31:16]) {
            0x0000: parse_server_name;
            default: skip_extension_stage_2;
        }
    }

    state skip_extension_stage_2 {
        bit<32> extension = pkt.lookahead<bit<32>>();
        transition select(extension[15:0]) {
            0x00: skip_extension_stage_2_len_0; 
            0x01: skip_extension_stage_2_len_1;
            0x02: skip_extension_stage_2_len_2;
            0x03: skip_extension_stage_2_len_3;
            0x04: skip_extension_stage_2_len_4;
            0x05: skip_extension_stage_2_len_5;
            0x06: skip_extension_stage_2_len_6;
            0x07: skip_extension_stage_2_len_7;
            0x08: skip_extension_stage_2_len_8;
            0x09: skip_extension_stage_2_len_9;
            0x0a: skip_extension_stage_2_len_10;
            0x0b: skip_extension_stage_2_len_11;
            0x0c: skip_extension_stage_2_len_12;
            0x0d: skip_extension_stage_2_len_13;
            0x0e: skip_extension_stage_2_len_14;
            0x0f: skip_extension_stage_2_len_15;
            0x10: skip_extension_stage_2_len_16;
            0x11: skip_extension_stage_2_len_17;
            0x12: skip_extension_stage_2_len_18;
            0x13: skip_extension_stage_2_len_19;
            0x14: skip_extension_stage_2_len_20;
            0x15: skip_extension_stage_2_len_21;
            0x16: skip_extension_stage_2_len_22;
            0x17: skip_extension_stage_2_len_23;
            0x18: skip_extension_stage_2_len_24;
            0x19: skip_extension_stage_2_len_25;
            0x1a: skip_extension_stage_2_len_26;
            0x1b: skip_extension_stage_2_len_27;
            0x1c: skip_extension_stage_2_len_28;
            0x1d: skip_extension_stage_2_len_29;
            0x1e: skip_extension_stage_2_len_30;
            0x20: skip_extension_stage_2_len_31;
            // default: parse_extension_long_1; 
            default: unparsed_extension; 
        }
    }

    state skip_extension_stage_2_len_0 {pkt.advance(32); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_1 {pkt.advance(40); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_2 {pkt.advance(48); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_3 {pkt.advance(56); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_4 {pkt.advance(64); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_5 {pkt.advance(72); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_6 {pkt.advance(80); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_7 {pkt.advance(88); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_8 {pkt.advance(96); transition parse_extension_stage_2; }
    state skip_extension_stage_2_len_9{pkt.advance(104); transition parse_extension_stage_2; }

    state skip_extension_stage_2_len_10 {pkt.advance(112); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_11 {pkt.advance(120); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_12 {pkt.advance(128); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_13 {pkt.advance(136); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_14 {pkt.advance(144); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_15 {pkt.advance(152); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_16 {pkt.advance(160); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_17 {pkt.advance(168); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_18 {pkt.advance(176); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_19 {pkt.advance(184); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_20 {pkt.advance(192); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_21 {pkt.advance(200); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_22 {pkt.advance(208); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_23 {pkt.advance(216); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_24 {pkt.advance(224); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_25 {pkt.advance(232); transition parse_extension_stage_2;}
    state skip_extension_stage_2_len_26 {pkt.advance(240); transition parse_extension_stage_2;}

    state skip_extension_stage_2_len_27 {pkt.advance(216); transition skip_extension_stage_2_len_0;}
    state skip_extension_stage_2_len_28 {pkt.advance(216); transition skip_extension_stage_2_len_1;}
    state skip_extension_stage_2_len_29 {pkt.advance(216); transition skip_extension_stage_2_len_2;}
    state skip_extension_stage_2_len_30 {pkt.advance(216); transition skip_extension_stage_2_len_3;}
    state skip_extension_stage_2_len_31 {pkt.advance(216); transition skip_extension_stage_2_len_4;}


    /////////////////////////////////////////////////////////////////////////////
    //////////////////////////  Extension stage 2 end //////////////////////////
    ///////////////////////////////////////////////////////////////////////////

    /////////////////////////////////////////////////////////////////////////////
    /////////////////////////  Extension long 1 start //////////////////////////
    ///////////////////////////////////////////////////////////////////////////

    state parse_extension_long_1 {
        pkt.extract(hdr.extension_long_1);
        transition select(hdr.extension_long_1.len[15:5]) {
            0x01: skip_extension_long_1_len_32;
            0x02: skip_extension_long_1_len_64;
            0x03: skip_extension_long_1_len_96;
            0x04: skip_extension_long_1_len_128;
            // 0x05: skip_extension_long_1_len_160;
            // 0x07: skip_extension_long_1_len_256;
            default: unparsed_extension;
        }
    }


    state skip_extension_long_1_len_16_1 {
        transition select(hdr.extension_long_1.len[4:3]) {
            0x00: skip_extension_long_1_len_8_0;
            0x01: skip_extension_long_1_len_8;
            0x02: skip_extension_long_1_len_16;
            0x03: skip_extension_long_1_len_24;
        }
    }

    state skip_extension_long_1_len_8_0 {
        transition select(hdr.extension_long_1.len[2:0]) {
            0x00: parse_extension_stage_2;
            0x01: skip_extension_long_1_len_1;
            0x02: skip_extension_long_1_len_2;
            0x03: skip_extension_long_1_len_3;
            0x04: skip_extension_long_1_len_4;
            0x05: skip_extension_long_1_len_5;
            0x06: skip_extension_long_1_len_6;
            0x07: skip_extension_long_1_len_7;
        }
    }

    state skip_extension_long_1_len_1  {pkt.advance(08); transition parse_extension_stage_2; }
    state skip_extension_long_1_len_2  {pkt.advance(16); transition parse_extension_stage_2; }
    state skip_extension_long_1_len_3  {pkt.advance(24); transition parse_extension_stage_2; }
    state skip_extension_long_1_len_4  {pkt.advance(32); transition parse_extension_stage_2; }
    state skip_extension_long_1_len_5  {pkt.advance(40); transition parse_extension_stage_2; }
    state skip_extension_long_1_len_6  {pkt.advance(48); transition parse_extension_stage_2; }
    state skip_extension_long_1_len_7  {pkt.advance(56); transition parse_extension_stage_2; }


    state skip_extension_long_1_len_8  {pkt.advance(64); transition skip_extension_long_1_len_8_0;}
    state skip_extension_long_1_len_16 {pkt.advance(128);transition skip_extension_long_1_len_8_0;}
    state skip_extension_long_1_len_24 {pkt.advance(192);transition skip_extension_long_1_len_8_0;}

    state skip_extension_long_1_len_32 {pkt.advance(256);transition skip_extension_long_1_len_16_1;} 
    state skip_extension_long_1_len_64 {pkt.advance(512);transition skip_extension_long_1_len_16_1;}
    state skip_extension_long_1_len_96 {pkt.advance(768);transition skip_extension_long_1_len_16_1;}
    state skip_extension_long_1_len_128 {pkt.advance(1024);transition skip_extension_long_1_len_16_1;}
    state skip_extension_long_1_len_160 {pkt.advance(1280);transition skip_extension_long_1_len_16_1;}

    state skip_extension_long_1_len_256 {pkt.advance(2048);transition skip_extension_long_1_len_16_1;}


    /////////////////////////////////////////////////////////////////////////////
    //////////////////////////  Extension long 1 end ///////////////////////////
    ///////////////////////////////////////////////////////////////////////////
    

    state parse_server_name {
        // pkt.extract(hdr.extension);
        pkt.advance(32);
        pkt.extract(hdr.client_servername); 
        transition select(hdr.client_servername.sni_len[15:5]) {
            0x00: parse_server_name_;
            0x01: parse_server_name_1;
            default: unparsed_sni;
        }
    }
    state unparsed_sni {
        meta.unparsed = SNI_LEN;
        transition accept;
    }

    state parse_server_name_ { 
        transition select(hdr.client_servername.sni_len[4:3]) {
            0x00: skip_part_16_8;
            0x01: extract_part_8;
            0x02: extract_part_16;
            0x03: extract_part_16_8;
        }
    }

    state parse_server_name_1{ 
        pkt.extract(hdr.servername_part32);
        transition parse_server_name_;
    }

    state skip_part_16_8 { 
        transition select(hdr.client_servername.sni_len[2:0]) {
            0x00: accept;
            0x01: extract_part_1;
            0x02: extract_part_2;
            0x03: extract_part_1_2;
            0x04: extract_part_4;
            0x05: extract_part_1_4;
            0x06: extract_part_2_4;
            0x07: extract_part_1_2_4;
        }
    }

    state extract_part_8 {
        pkt.extract(hdr.servername_part8);
        transition skip_part_16_8;
    }

    state extract_part_16 {
        pkt.extract(hdr.servername_part16);
        transition skip_part_16_8;
    }

    state extract_part_16_8 {
        pkt.extract(hdr.servername_part16);
        pkt.extract(hdr.servername_part8);
        transition skip_part_16_8;
    }

    state extract_part_1 {
        pkt.extract(hdr.servername_part1);
        transition accept;
    }
    state extract_part_2 {
        pkt.extract(hdr.servername_part2);
        transition accept;
    }
    state extract_part_1_2 {
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part1);
        transition accept;
    }
    state extract_part_4 {
        pkt.extract(hdr.servername_part4);
        transition accept;
    }
    state extract_part_1_4 {
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part1);
        transition accept;
    }
    state extract_part_2_4 {
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part2);
        transition accept;
    }
    state extract_part_1_2_4 {
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part1);
        transition accept;
    }

}