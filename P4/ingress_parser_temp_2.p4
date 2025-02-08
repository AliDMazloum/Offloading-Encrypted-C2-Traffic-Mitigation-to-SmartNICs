
/***********************  P A R S E R  **************************/

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    ParserCounter() extensions_length_counter;
    ParserCounter() extensions_count_counter;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
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
        transition parse_ipv4_features;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp_ports;
            default : accept;
        }
    }

    state parse_ipv4_features {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp_ports_features;
            default : accept;
        }
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

    state parse_tcp_ports_features {
        pkt.extract(hdr.tcp_ports);
        transition accept;
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
        pkt.extract(hdr.tls_client_hello);
        transition parse_session_ids;
        // transition parse_extensions_len;
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
        pkt.extract(hdr.compressions);
        // bit<8> compressions = pkt.lookahead<bit<8>>();
        transition select (hdr.compressions.len) {
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

    state parse_tls_server_hello {
        pkt.extract(hdr.tls_server_hello);
        transition parse_server_session_ids;
        // transition parse_extensions_len;
    }

    state parse_server_session_ids {
        pkt.extract(hdr.hello_server_session);
        transition select(hdr.hello_server_session.len[7:4]) {
            0x00: skip_server_session_len_16_0;
            0x01: skip_server_session_len_16_1;
            0x02: skip_server_session_len_32_1;
            0x03: skip_server_session_len_48_1;
            default: unparsed_server_session;
        }
    }

    state unparsed_server_session {
        meta.unparsed = SESSION_LEN;
        transition accept;
    }

    state skip_server_session_len_16_0 {
        transition select(hdr.hello_server_session.len[3:3]) {
            0x00: skip_server_session_len_8_0;
            0x01: skip_server_session_len_8_1;
        }
    }

    state skip_server_session_len_8_1 {pkt.advance(64);transition skip_server_session_len_8_0;}
    state skip_server_session_len_16_1 {pkt.advance(128);transition skip_server_session_len_16_0;}
    state skip_server_session_len_32_1 {pkt.advance(256);transition skip_server_session_len_16_0;}
    state skip_server_session_len_48_1 {pkt.advance(384);transition skip_server_session_len_16_0;}

    state skip_server_session_len_8_0 {
        transition select(hdr.hello_server_session.len[2:0]) {
            0x00: skip_server_session_len_0;
            0x01: skip_server_session_len_1;
            0x02: skip_server_session_len_2;
            0x03: skip_server_session_len_3;
            0x04: skip_server_session_len_4;
            0x05: skip_server_session_len_5;
            0x06: skip_server_session_len_6;
            0x07: skip_server_session_len_7;
        }
    }

    state skip_server_session_len_0 {pkt.advance(24); transition parse_extensions_len;} //skip cipher and compression, they are 24 always 
    state skip_server_session_len_1 {pkt.advance(32); transition parse_extensions_len;}
    state skip_server_session_len_2 {pkt.advance(40); transition parse_extensions_len;}
    state skip_server_session_len_3 {pkt.advance(48); transition parse_extensions_len;}
    state skip_server_session_len_4 {pkt.advance(56); transition parse_extensions_len;}
    state skip_server_session_len_5 {pkt.advance(64); transition parse_extensions_len;}
    state skip_server_session_len_6 {pkt.advance(72); transition parse_extensions_len;}
    state skip_server_session_len_7 {pkt.advance(80); transition parse_extensions_len;}

    state parse_extensions_len {
        pkt.extract(hdr.extensions_len);
        extensions_length_counter.set(hdr.extensions_len.len_part1);
        // meta.extensions_count = 1;
        // transition accept;
        transition prase_extension_1;
    }

    /////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    ///////////////////////////////////////Extension 1 Parsing Start \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    /////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\


    state prase_extension_1 {
        pkt.extract(hdr.extension_1);
        extensions_length_counter.decrement(2);
        transition select(hdr.extension_1.len[7:4]) {
            0x00: skip_extension_1_len_16_0;
            0x01: skip_extension_1_len_16;
            0x02: skip_extension_1_len_32;
            0x03: skip_extension_1_len_48;
            0x04: skip_extension_1_len_64;
            default: unparsed_extension_1;
        }
    }

    state unparsed_extension_1 {meta.extensions_count = 11;transition accept;}

    state skip_extension_1_len_16 {pkt.advance(128); extensions_length_counter.decrement(16); transition skip_extension_1_len_16_0;}
    state skip_extension_1_len_32 {pkt.advance(256); extensions_length_counter.decrement(32); transition skip_extension_1_len_16_0;}
    state skip_extension_1_len_48 {pkt.advance(384); extensions_length_counter.decrement(48); transition skip_extension_1_len_16_0;}
    state skip_extension_1_len_64 {pkt.advance(512); extensions_length_counter.decrement(64); transition skip_extension_1_len_16_0;}

    state skip_extension_1_len_16_0 {
        transition select(hdr.extension_1.len[3:3]) {
            0x00: skip_extension_1_len_8_0;
            0x01: skip_extension_1_len_8;
        }
    }

    state skip_extension_1_len_8 {pkt.advance(64); extensions_length_counter.decrement(8); transition skip_extension_1_len_8_0;}

    state skip_extension_1_len_8_0 {
        transition select(hdr.extension_1.len[2:0]) {
            0x00: check_extensions_length_counter_extension_1;
            0x01: skip_extension_1_len_1;
            0x02: skip_extension_1_len_2;
            0x03: skip_extension_1_len_3;
            0x04: skip_extension_1_len_4;
            0x05: skip_extension_1_len_5;
            0x06: skip_extension_1_len_6;
            0x07: skip_extension_1_len_7;
        }
    }

    state skip_extension_1_len_1 {pkt.advance(08); extensions_length_counter.decrement(1); transition check_extensions_length_counter_extension_1;}
    state skip_extension_1_len_2 {pkt.advance(16); extensions_length_counter.decrement(2); transition check_extensions_length_counter_extension_1;}
    state skip_extension_1_len_3 {pkt.advance(24); extensions_length_counter.decrement(3); transition check_extensions_length_counter_extension_1;}
    state skip_extension_1_len_4 {pkt.advance(32); extensions_length_counter.decrement(4); transition check_extensions_length_counter_extension_1;}
    state skip_extension_1_len_5 {pkt.advance(40); extensions_length_counter.decrement(5); transition check_extensions_length_counter_extension_1;}
    state skip_extension_1_len_6 {pkt.advance(48); extensions_length_counter.decrement(6); transition check_extensions_length_counter_extension_1;}
    state skip_extension_1_len_7 {pkt.advance(56); extensions_length_counter.decrement(7); transition check_extensions_length_counter_extension_1;}

    state check_extensions_length_counter_extension_1{
        transition select(extensions_length_counter.is_zero()) {
            true: set_extenstion_count_1;
            false: prase_extension_2;
        }
    }
    state set_extenstion_count_1 {
        meta.extensions_count = 1;
        transition accept;
    }


    /////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    ///////////////////////////////////////Extension 2 Parsing Start \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    /////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    state prase_extension_2 {
        pkt.extract(hdr.extension_2);
        extensions_length_counter.decrement(2);
        transition select(hdr.extension_2.len[7:4]) {
            0x00: skip_extension_2_len_16_0;
            0x01: skip_extension_2_len_16;
            0x02: skip_extension_2_len_32;
            0x03: skip_extension_2_len_48;
            0x04: skip_extension_2_len_64;
            default: unparsed_extension_2;
        }
    }

    state unparsed_extension_2 {meta.extensions_count = 11;transition accept;}

    state skip_extension_2_len_16 {pkt.advance(128); extensions_length_counter.decrement(16); transition skip_extension_2_len_16_0;}
    state skip_extension_2_len_32 {pkt.advance(256); extensions_length_counter.decrement(32); transition skip_extension_2_len_16_0;}
    state skip_extension_2_len_48 {pkt.advance(384); extensions_length_counter.decrement(48); transition skip_extension_2_len_16_0;}
    state skip_extension_2_len_64 {pkt.advance(512); extensions_length_counter.decrement(64); transition skip_extension_2_len_16_0;}

    state skip_extension_2_len_16_0 {
        transition select(hdr.extension_2.len[3:3]) {
            0x00: skip_extension_2_len_8_0;
            0x01: skip_extension_2_len_8;
        }
    }

    state skip_extension_2_len_8 {pkt.advance(64); extensions_length_counter.decrement(8); transition skip_extension_2_len_8_0;}

    state skip_extension_2_len_8_0 {
        transition select(hdr.extension_2.len[2:0]) {
            0x00: check_extensions_length_counter_extension_2;
            0x01: skip_extension_2_len_1;
            0x02: skip_extension_2_len_2;
            0x03: skip_extension_2_len_3;
            0x04: skip_extension_2_len_4;
            0x05: skip_extension_2_len_5;
            0x06: skip_extension_2_len_6;
            0x07: skip_extension_2_len_7;
        }
    }

    state skip_extension_2_len_1 {pkt.advance(08); extensions_length_counter.decrement(1); transition check_extensions_length_counter_extension_2;}
    state skip_extension_2_len_2 {pkt.advance(16); extensions_length_counter.decrement(2); transition check_extensions_length_counter_extension_2;}
    state skip_extension_2_len_3 {pkt.advance(24); extensions_length_counter.decrement(3); transition check_extensions_length_counter_extension_2;}
    state skip_extension_2_len_4 {pkt.advance(32); extensions_length_counter.decrement(4); transition check_extensions_length_counter_extension_2;}
    state skip_extension_2_len_5 {pkt.advance(40); extensions_length_counter.decrement(5); transition check_extensions_length_counter_extension_2;}
    state skip_extension_2_len_6 {pkt.advance(48); extensions_length_counter.decrement(6); transition check_extensions_length_counter_extension_2;}
    state skip_extension_2_len_7 {pkt.advance(56); extensions_length_counter.decrement(7); transition check_extensions_length_counter_extension_2;}

    state check_extensions_length_counter_extension_2{
        transition select(extensions_length_counter.is_zero()) {
            true: set_extenstion_count_2;
            false: reject;
        }
    }
    state set_extenstion_count_2 {
        meta.extensions_count = 2;
        transition accept;
    }

    /////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    ///////////////////////////////////////Extension 3 Parsing Start \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    /////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    state prase_extension_3 {
        pkt.extract(hdr.extension_3);
        extensions_length_counter.decrement(2);
        transition select(hdr.extension_3.len[7:4]) {
            0x00: skip_extension_3_len_16_0;
            0x01: skip_extension_3_len_16;
            0x02: skip_extension_3_len_32;
            0x03: skip_extension_3_len_48;
            0x04: skip_extension_3_len_64;
            default: unparsed_extension_3;
        }
    }

    state unparsed_extension_3 {meta.extensions_count = 11;transition accept;}

    state skip_extension_3_len_16 {pkt.advance(128); extensions_length_counter.decrement(16); transition skip_extension_3_len_16_0;}
    state skip_extension_3_len_32 {pkt.advance(256); extensions_length_counter.decrement(32); transition skip_extension_3_len_16_0;}
    state skip_extension_3_len_48 {pkt.advance(384); extensions_length_counter.decrement(48); transition skip_extension_3_len_16_0;}
    state skip_extension_3_len_64 {pkt.advance(512); extensions_length_counter.decrement(64); transition skip_extension_3_len_16_0;}

    state skip_extension_3_len_16_0 {
        transition select(hdr.extension_3.len[3:3]) {
            0x00: skip_extension_3_len_8_0;
            0x01: skip_extension_3_len_8;
        }
    }

    state skip_extension_3_len_8 {pkt.advance(64); extensions_length_counter.decrement(8); transition skip_extension_3_len_8_0;}

    state skip_extension_3_len_8_0 {
        transition select(hdr.extension_3.len[2:0]) {
            0x00: check_extensions_length_counter_extension_3;
            0x01: skip_extension_3_len_1;
            0x02: skip_extension_3_len_2;
            0x03: skip_extension_3_len_3;
            0x04: skip_extension_3_len_4;
            0x05: skip_extension_3_len_5;
            0x06: skip_extension_3_len_6;
            0x07: skip_extension_3_len_7;
        }
    }

    state skip_extension_3_len_1 {pkt.advance(08); extensions_length_counter.decrement(1); transition check_extensions_length_counter_extension_3;}
    state skip_extension_3_len_2 {pkt.advance(16); extensions_length_counter.decrement(2); transition check_extensions_length_counter_extension_3;}
    state skip_extension_3_len_3 {pkt.advance(24); extensions_length_counter.decrement(3); transition check_extensions_length_counter_extension_3;}
    state skip_extension_3_len_4 {pkt.advance(32); extensions_length_counter.decrement(4); transition check_extensions_length_counter_extension_3;}
    state skip_extension_3_len_5 {pkt.advance(40); extensions_length_counter.decrement(5); transition check_extensions_length_counter_extension_3;}
    state skip_extension_3_len_6 {pkt.advance(48); extensions_length_counter.decrement(6); transition check_extensions_length_counter_extension_3;}
    state skip_extension_3_len_7 {pkt.advance(56); extensions_length_counter.decrement(7); transition check_extensions_length_counter_extension_3;}

    state check_extensions_length_counter_extension_3{
        transition select(extensions_length_counter.is_zero()) {
            true: set_extenstion_count_3;
            false: set_extenstion_count_3;
        }
    }
    state set_extenstion_count_3 {
        meta.extensions_count = 3;
        transition accept;
    }
    

    //////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    ///////////////////////////////////////Extension 4 Parsing Start \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    //////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    state prase_extension_4 {
        pkt.extract(hdr.extension_4);
        extensions_length_counter.decrement(32);
        transition select(hdr.extension_4.len[7:2]) {
            0x000: skip_extension_4_len_4_0;
            0x001: skip_extension_4_len_4;
            0x010: skip_extension_4_len_8;
            0x011: skip_extension_4_len_12;
            0x100: skip_extension_4_len_16;
            default: unparsed_extension_4;
        }
    }

    state unparsed_extension_4 {meta.unparsed = 1;transition accept;}

    state skip_extension_4_len_4 {pkt.advance(32); extensions_length_counter.decrement(32); transition skip_extension_4_len_4_0;}
    state skip_extension_4_len_8 {pkt.advance(64); extensions_length_counter.decrement(64); transition skip_extension_4_len_4_0;}
    state skip_extension_4_len_12 {pkt.advance(96); extensions_length_counter.decrement(96); transition skip_extension_4_len_4_0;}
    state skip_extension_4_len_16 {pkt.advance(128); extensions_length_counter.decrement(128); transition skip_extension_4_len_4_0;}

    state skip_extension_4_len_4_0 {
        transition select(hdr.extension_4.len[1:0]) {
            0x00: check_extensions_length_counter_extension_4;
            0x01: skip_extension_4_len_1;
            0x10: skip_extension_4_len_2;
            0x11: skip_extension_4_len_3;
        }
    }

    state skip_extension_4_len_1 {pkt.advance(08); extensions_length_counter.decrement(8); transition check_extensions_length_counter_extension_4;}
    state skip_extension_4_len_2 {pkt.advance(16); extensions_length_counter.decrement(16); transition check_extensions_length_counter_extension_4;}
    state skip_extension_4_len_3 {pkt.advance(24); extensions_length_counter.decrement(24); transition check_extensions_length_counter_extension_4;}
    
    state check_extensions_length_counter_extension_4{
        transition select(extensions_length_counter.is_zero()) {
            true: set_extenstion_count_4;
            false: set_extenstion_count_4;
        }
    }
    state set_extenstion_count_4 {
        meta.extensions_count = 4;
        transition accept;
    }

    ///////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    ///////////////////////////////////////Extension 5 Parsing Start \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    ///////////////////////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

    // state prase_extension_5 {
    //     pkt.extract(hdr.extension_5);
    //     // extensions_length_counter.decrement(hdr.extension_5.len[7:0]);

    //     transition select(hdr.extension_5.len[13:4]) {
    //         0x00: parse_extension_5_len_16_0;
    //         0x01: parse_extension_5_len_16_1;
    //         0x02: parse_extension_5_len_32_1;
    //         0x03: parse_extension_5_len_48_1;
    //         0x04: parse_extension_5_len_64_1;
    //         default: unparsed_extension_5;
    //     }
    // }

    // state unparsed_extension_5 {meta.unparsed = 1;transition accept;}

    // state parse_extension_5_len_16_0 {
    //     transition select(hdr.extension_5.len[3:1]) {
    //         0x00: check_extensions_length_counter_extension_5;
    //         0x01: parse_extension_5_len_1;
    //         0x02: parse_extension_5_len_2;
    //         0x03: parse_extension_5_len_3;
    //         0x04: parse_extension_5_len_4;
    //         0x05: parse_extension_5_len_5;
    //         0x06: parse_extension_5_len_6;
    //         0x07: parse_extension_5_len_7;
    //     }
    // }

    // state parse_extension_5_len_16_1 {pkt.advance(128);transition parse_extension_5_len_16_0;}
    // state parse_extension_5_len_32_1 {pkt.advance(256);transition parse_extension_5_len_16_0;}
    // state parse_extension_5_len_48_1 {pkt.advance(384);transition parse_extension_5_len_16_0;}
    // state parse_extension_5_len_64_1 {pkt.advance(512);transition parse_extension_5_len_16_0;}

    // state parse_extension_5_len_1 {pkt.advance(016); transition check_extensions_length_counter_extension_5;}
    // state parse_extension_5_len_2 {pkt.advance(032); transition check_extensions_length_counter_extension_5;}
    // state parse_extension_5_len_3 {pkt.advance(048); transition check_extensions_length_counter_extension_5;}
    // state parse_extension_5_len_4 {pkt.advance(064); transition check_extensions_length_counter_extension_5;}
    // state parse_extension_5_len_5 {pkt.advance(080); transition check_extensions_length_counter_extension_5;}
    // state parse_extension_5_len_6 {pkt.advance(096); transition check_extensions_length_counter_extension_5;}
    // state parse_extension_5_len_7 {pkt.advance(112); transition check_extensions_length_counter_extension_5;}

    // state check_extensions_length_counter_extension_5{
    //     transition select(extensions_length_counter.is_zero()) {
    //         true: set_extenstion_count_5;
    //         false: set_extenstion_count_5;
    //     }
    // }
    // state set_extenstion_count_5 {
    //     meta.extensions_count = 5;
    //     transition accept;
    // }

    

}