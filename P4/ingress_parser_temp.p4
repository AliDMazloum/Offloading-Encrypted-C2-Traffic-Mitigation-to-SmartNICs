
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
        transition parse_extensions_len;
    }


    state parse_tls_server_hello {
        pkt.extract(hdr.tls_server_hello);
        transition parse_extensions_len;
    }

    state parse_extensions_len {
        pkt.extract(hdr.extensions_len);
        // extensions_length_counter.set(hdr.extensions_len.len_part1);
        // extensions_length_counter.set(8w5);
        // extensions_length_counter.decrement(8w5);
        transition set_extensions_count_counter;
    }

    // state set_extensions_length_counter {
    //     extensions_length_counter.set(hdr.extensions_len.len_part1);
    //     transition set_extensions_count_counter;
    // }

    state set_extensions_count_counter {
        extensions_count_counter.set(8w7);
        transition get_extenstions_pre_check;
    }


    state get_extenstions_pre_check {
        transition select(extensions_count_counter.is_negative()) {
            true: accept;
            false: get_extenstions_count_1;
        }
    }
    
    state get_extenstions_count_1 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_1;
            false: get_extenstions_count_2;
        }
    }
    state set_extenstions_count_1 {
        meta.extensions_count = 1;
        transition accept;
    }

    state get_extenstions_count_2 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_2;
            false: get_extenstions_count_3;
        }
    }
    state set_extenstions_count_2 {
        meta.extensions_count = 2;
        transition accept;
    }

    state get_extenstions_count_3 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_3;
            false: get_extenstions_count_4;
        }
    }
    state set_extenstions_count_3 {
        meta.extensions_count = 3;
        transition accept;
    }

    state get_extenstions_count_4 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_4;
            false: get_extenstions_count_5;
        }
    }
    state set_extenstions_count_4 {
        meta.extensions_count = 4;
        transition accept;
    }

    state get_extenstions_count_5 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_5;
            false: get_extenstions_count_6;
        }
    }
    state set_extenstions_count_5 {
        meta.extensions_count = 5;
        transition accept;
    }

    state get_extenstions_count_6 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_6;
            false: get_extenstions_count_7;
        }
    }
    state set_extenstions_count_6 {
        meta.extensions_count = 6;
        transition accept;
    }

    state get_extenstions_count_7 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_7;
            false: get_extenstions_count_8;
        }
    }
    state set_extenstions_count_7 {
        meta.extensions_count = 7;
        transition accept;
    }

    state get_extenstions_count_8 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_8;
            false: get_extenstions_count_9;
        }
    }
    state set_extenstions_count_8 {
        meta.extensions_count = 8;
        transition accept;
    }

    state get_extenstions_count_9 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_9;
            false: get_extenstions_count_10;
        }
    }
    state set_extenstions_count_9 {
        meta.extensions_count = 9;
        transition accept;
    }

    state get_extenstions_count_10 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_10;
            false: get_extenstions_count_11;
        }
    }
    state set_extenstions_count_10 {
        meta.extensions_count = 10;
        transition accept;
    }

    state get_extenstions_count_11 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_11;
            false: get_extenstions_count_12;
        }
    }
    state set_extenstions_count_11 {
        meta.extensions_count = 11;
        transition accept;
    }

    state get_extenstions_count_12 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_12;
            false: get_extenstions_count_13;
        }
    }
    state set_extenstions_count_12 {
        meta.extensions_count = 12;
        transition accept;
    }

    state get_extenstions_count_13 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_13;
            false: get_extenstions_count_14;
        }
    }
    state set_extenstions_count_13 {
        meta.extensions_count = 13;
        transition accept;
    }

    state get_extenstions_count_14 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_14;
            false: get_extenstions_count_15;
        }
    }
    state set_extenstions_count_14 {
        meta.extensions_count = 14;
        transition accept;
    }

    state get_extenstions_count_15 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_15;
            false: get_extenstions_count_16;
        }
    }
    state set_extenstions_count_15 {
        meta.extensions_count = 15;
        transition accept;
    }

    state get_extenstions_count_16 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_16;
            false: get_extenstions_count_17;
        }
    }
    state set_extenstions_count_16 {
        meta.extensions_count = 16;
        transition accept;
    }

    state get_extenstions_count_17 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_17;
            false: get_extenstions_count_18;
        }
    }
    state set_extenstions_count_17 {
        meta.extensions_count = 17;
        transition accept;
    }

    state get_extenstions_count_18 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_18;
            false: get_extenstions_count_19;
        }
    }
    state set_extenstions_count_18 {
        meta.extensions_count = 18;
        transition accept;
    }

    state get_extenstions_count_19 {
        extensions_count_counter.decrement(8w1);
        transition select(extensions_count_counter.is_zero()) {
            true: set_extenstions_count_19;
            false: get_extenstions_count_20;
        }
    }
    state set_extenstions_count_19 {
        meta.extensions_count = 19;
        transition accept;
    }

    state get_extenstions_count_20 {
        meta.extensions_count = 20;
        extensions_count_counter.decrement(8w1);
        transition accept;
    }
// state set_counters {
    //     // meta.extensions_count = 0;
    //     // extensions_length_counter.set(hdr.extensions_len.len_part1);
    //     // extensions_count_counter.set(8w1);
    //     // meta.extensions_count = 12;
    //     transition get_extenstions_pre_check;
    // }

    // state check_extensions_length_counter {
    //     transition select(extensions_length_counter.is_zero()) {
    //         true: get_extenstions_count_1;
    //         false: parse_extension;
    //     }
    // }

    // /////////////////////////////////////////////////////////////////////////////
    // //////////////////////////  Extension Parsing Start ////////////////////////
    // ///////////////////////////////////////////////////////////////////////////

    // state parse_extension {
    //     extensions_count_counter.increment(8w1);
    //     transition skip_extension;
    //     // meta.extensions_count = 1;
    //     // transition accept;
    // }

    // state unparsed_extension {
    //     meta.unparsed = EXT_LIM;
    //     transition accept;
    // }


    // state skip_extension {
    //     bit<32> extension = pkt.lookahead<bit<32>>();
    //     transition select(extension[15:0]) {
    //         0x00: skip_extension_len_0; 
    //         0x01: skip_extension_len_1;
    //         0x02: skip_extension_len_2;
    //         0x03: skip_extension_len_3;
    //         0x04: skip_extension_len_4;
    //         0x05: skip_extension_len_5;
    //         0x06: skip_extension_len_6;
    //         0x07: skip_extension_len_7;
    //         0x08: skip_extension_len_8;
    //         0x09: skip_extension_len_9;
    //         0x0a: skip_extension_len_10;
    //         0x0b: skip_extension_len_11;
    //         0x0c: skip_extension_len_12;
    //         0x0d: skip_extension_len_13;
    //         0x0e: skip_extension_len_14;
    //         0x0f: skip_extension_len_15;
    //         0x10: skip_extension_len_16;
    //         0x11: skip_extension_len_17;
    //         0x12: skip_extension_len_18;
    //         0x13: skip_extension_len_19;
    //         0x14: skip_extension_len_20;
    //         0x15: skip_extension_len_21;
    //         0x16: skip_extension_len_22;
    //         0x17: skip_extension_len_23;
    //         0x18: skip_extension_len_24;
    //         0x19: skip_extension_len_25;
    //         0x1a: skip_extension_len_26;
    //         0x1b: skip_extension_len_27;
    //         0x1c: skip_extension_len_28;
    //         0x1d: skip_extension_len_29;
    //         0x1e: skip_extension_len_30;
    //         0x20: skip_extension_len_31;
    //         default: accept; 
    //     }
    // }

    // state skip_extension_len_0 {
    //     pkt.advance(32); 
    //     extensions_length_counter.decrement(8w32);
    //     transition check_extensions_length_counter; 
    // }

    // state skip_extension_len_1 {
    //     pkt.advance(40);
    //     extensions_length_counter.decrement(8w40); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_2 {
    //     pkt.advance(48);
    //     extensions_length_counter.decrement(8w48); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_3 {
    //     pkt.advance(56);
    //     extensions_length_counter.decrement(8w56); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_4 {
    //     pkt.advance(64);
    //     extensions_length_counter.decrement(8w64); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_5 {
    //     pkt.advance(72);
    //     extensions_length_counter.decrement(8w72); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_6 {
    //     pkt.advance(80);
    //     extensions_length_counter.decrement(8w80); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_7 {
    //     pkt.advance(88);
    //     extensions_length_counter.decrement(8w88); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_8 {
    //     pkt.advance(96);
    //     extensions_length_counter.decrement(8w96); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_9 {
    //     pkt.advance(104);
    //     extensions_length_counter.decrement(8w104); 
    //     transition check_extensions_length_counter;
    // }
    
    // state skip_extension_len_10 {
    //     pkt.advance(112); 
    //     extensions_length_counter.decrement(8w112); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_11 {
    //     pkt.advance(120); 
    //     extensions_length_counter.decrement(8w120); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_12 {
    //     pkt.advance(128); 
    //     extensions_length_counter.decrement(8w128); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_13 {
    //     pkt.advance(136); 
    //     extensions_length_counter.decrement(8w136); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_14 {
    //     pkt.advance(144); 
    //     extensions_length_counter.decrement(8w144); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_15 {
    //     pkt.advance(152); 
    //     extensions_length_counter.decrement(8w152); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_16 {
    //     pkt.advance(160); 
    //     extensions_length_counter.decrement(8w160); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_17 {
    //     pkt.advance(168); 
    //     extensions_length_counter.decrement(8w168); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_18 {
    //     pkt.advance(176); 
    //     extensions_length_counter.decrement(8w176); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_19 {
    //     pkt.advance(184); 
    //     extensions_length_counter.decrement(8w184); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_20 {
    //     pkt.advance(192); 
    //     extensions_length_counter.decrement(8w192); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_21 {
    //     pkt.advance(200); 
    //     extensions_length_counter.decrement(8w200); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_22 {
    //     pkt.advance(208); 
    //     extensions_length_counter.decrement(8w208); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_23 {
    //     pkt.advance(216); 
    //     extensions_length_counter.decrement(8w216); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_24 {
    //     pkt.advance(224); 
    //     extensions_length_counter.decrement(8w224); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_25 {
    //     pkt.advance(232); 
    //     extensions_length_counter.decrement(8w232); 
    //     transition check_extensions_length_counter;
    // }

    // state skip_extension_len_26 {
    //     pkt.advance(240); 
    //     extensions_length_counter.decrement(8w240); 
    //     transition check_extensions_length_counter;
    // }


    // state skip_extension_len_27 {
    //     pkt.advance(216); 
    //     extensions_length_counter.decrement(8w216); 
    //     transition skip_extension_len_0;
    // }

    // state skip_extension_len_28 {
    //     pkt.advance(216); 
    //     extensions_length_counter.decrement(8w216); 
    //     transition skip_extension_len_1;
    // }

    // state skip_extension_len_29 {
    //     pkt.advance(216); 
    //     extensions_length_counter.decrement(8w216); 
    //     transition skip_extension_len_2;
    // }

    // state skip_extension_len_30 {
    //     pkt.advance(216); 
    //     extensions_length_counter.decrement(8w216); 
    //     transition skip_extension_len_3;
    // }

    // state skip_extension_len_31 {
    //     pkt.advance(216); 
    //     extensions_length_counter.decrement(8w216); 
    //     transition skip_extension_len_4;
    // }
    

}