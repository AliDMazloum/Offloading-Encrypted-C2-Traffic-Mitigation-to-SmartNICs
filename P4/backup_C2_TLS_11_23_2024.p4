/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>
/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const bit<16>       TYPE_IPV4 = 0x800;
const bit<16>       TYPE_RECIRC = 0x88B5;
const bit<8>        TYPE_TCP = 6;
const bit<8>        TYPE_UDP = 17;
const bit<32>       MAX_REGISTER_ENTRIES = 2048;
#define INDEX_WIDTH 16
/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
header Ethernet_h {
	bit<48> dst_addr;
	bit<48> src_add;
	bit<16> ether_type;
}

header IPv4_h {
	bit<4> version;
	bit<4> ihl;
	bit<8> diffserv;
	bit<16> total_len;
	bit<16> identification;
	bit<3> flags;
	bit<13> flag_offset;
	bit<8> ttl;
	bit<8> protocol;
	bit<16> hdr_checksum;
	bit<32> src_addr;
	bit<32> dst_addr;
}

header TCP_h {
	bit<16> src_port;
	bit<16> dst_port;
	bit<32> seq_no;
	bit<32> ack_no;
	bit<4> data_offset;
	bit<4> res;
	bit<8> flags;
	bit<16> window;
	bit<16> checksum;
	bit<16> urgent_ptr;
}

header TCP_after_h {
}

header TCP_options_h {
	bit<96> options;
}

header TLS_h {
	bit<8> type;
	bit<16> version;
	bit<16> len;
}

header TLS_handshake_h {
	bit<8> type;
	bit<24> len;
	bit<16> version;
	bit<256> random;
}

header TLS_session_h {
	bit<8> len;
}

header TLS_cipher_h {
	bit<16> len;
}

header TLS_compression_h {
	bit<8> len;
}

header TLS_extentions_len_h {
	bit<16> len;
}

header TLS_extention_h {
	bit<16> type;
	bit<16> len;
}

header client_servername_part1_h {
	bit<8> part1;
}

header client_servername_part2_h {
	bit<16> part2;
}

header client_servername_part4_h {
	bit<32> part4;
}

header client_servername_part8_h {
	bit<64> part8;
}

header client_servername_part16_h {
	bit<128> part16;
}

header client_servername_part32_h {
	bit<256> part32;
}

header client_servername_h {
	bit<8> type;
	bit<16> len;
	bit<16> sni_list_len;
	bit<16> sni_len;
}

header SCTP_h {
	bit<16> src_port;
	bit<16> dst_port;
	bit<32> tag;
	bit<32> checksum;
}

header SCTP_chunk_h {
	bit<8> chunk_type;
	bit<8> chunk_flags;
	bit<16> len;
}

header SCTP_chunk_data_h {
	bit<8> chunk_type;
	bit<8> chunk_flags;
	bit<16> len;
	bit<32> TSN;
	bit<16> stream_identifier;
	bit<16> stream_sequence_number;
	bit<32> PPID;
}

header NGAP_h {
	bit<8> procedure_code;
	bit<8> criticality;
}

/*Custom header for recirculation*/
header recirc_h {
    bit<8>       class_result;
}

header packet_lengths_h {
    bit<16> pkt_len_0;
    bit<16> pkt_len_1;
    bit<16> pkt_len_2;
    bit<16> pkt_len_3;
    bit<16> pkt_len_4;
    bit<16> pkt_len_5;
    bit<16> pkt_len_6;
    bit<16> pkt_len_7;
    bit<16> pkt_len_8;
    bit<16> pkt_len_9;

}

/***********************  H E A D E R S  ************************/
struct my_ingress_headers_t {
    // ethernet_h   Ethernet;
    // recirc_h     recirc;
    // ipv4_h       IPv4;
    // tcp_h        TCP;
    // udp_h        udp;
    Ethernet_h Ethernet;
    recirc_h     recirc;
    packet_lengths_h packet_lengths;
	IPv4_h IPv4;
	TCP_h TCP;
	TCP_after_h TCP_after;
	TCP_options_h TCP_options;
	TLS_h TLS;
	TLS_handshake_h TLS_handshake;
	TLS_session_h TLS_session;
	TLS_cipher_h TLS_cipher;
	TLS_compression_h TLS_compression;
	TLS_extentions_len_h TLS_extentions_len;
	TLS_extention_h TLS_extention;
	client_servername_h client_servername;
	client_servername_part1_h client_servername_part1;
	client_servername_part2_h client_servername_part2;
	client_servername_part4_h client_servername_part4;
	client_servername_part8_h client_servername_part8;
	client_servername_part16_h client_servername_part16;
	client_servername_part32_h client_servername_part32;
	SCTP_h SCTP;
	SCTP_chunk_h SCTP_chunk;
	SCTP_chunk_data_h SCTP_chunk_data;
	NGAP_h NGAP;
}

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
struct my_ingress_metadata_t {
    bit<8> classified_flag;

    bit<1>  reg_status;
    bit<(INDEX_WIDTH)> flow_ID;
    bit<(INDEX_WIDTH)> rev_flow_ID;
    bit<(INDEX_WIDTH)> register_index;

    bit<1> direction;

    bit<8> pkt_count;

    bit<16> pkt_len_0;
    bit<16> pkt_len_1;
    bit<16> pkt_len_2;
    bit<16> pkt_len_3;
    bit<16> pkt_len_4;
    bit<16> pkt_len_5;
    bit<16> pkt_len_6;
    bit<16> pkt_len_7;
    bit<16> pkt_len_8;
    bit<16> pkt_len_9;

    bit<8> class0;
    bit<8> class1;
    bit<8> class2;
    bit<8> class3;
    bit<8> class4;
    
    bit<8> final_class;

    bit<308> codeword0;
    bit<358> codeword1;
    bit<305> codeword2;
    bit<318> codeword3;
    bit<325> codeword4;
}

struct flow_class_digest {  // maximum size allowed is 47 bytes
    
    ipv4_addr_t  source_addr;   // 32 bits
    ipv4_addr_t  destin_addr;   // 32 bits
    bit<16> source_port;
    bit<16> destin_port;
    bit<8> protocol;
    bit<8> class_value;
    bit<8> packet_num;
    bit<(INDEX_WIDTH)> register_index; // To send info to the controller
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }
    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }
    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.Ethernet);
        transition select(hdr.Ethernet.ether_type) {
            TYPE_RECIRC : parse_recirc;
            TYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_recirc {
       pkt.extract(hdr.recirc);
       transition parse_ipv4;
    }

    state parse_ipv4 {
        pkt.extract(hdr.IPv4);
        meta.final_class=10;
        transition select(hdr.IPv4.protocol){
			6: parse_TCP_state1;
			132: parse_SCTP_state1;
			default: accept;
		}
    }

    state parse_TCP_state1 {
        pkt.extract(hdr.TCP);
		transition select(hdr.TCP.data_offset){
			5: parse_TCP_after_state1;
			8: parse_TCP_options_state1;
			default: accept;
		}
    }

    state parse_TCP_after_state1 {
		pkt.extract(hdr.TCP_after);
		transition select(hdr.TCP.dst_port){
			443: parse_TLS_state1;
			default: accept;
		}
	}


	state parse_TCP_options_state1 {
		pkt.extract(hdr.TCP_options);
		transition select(hdr.TCP.dst_port){
			443: parse_TLS_state1;
			default: accept;
		}
	}

    state parse_SCTP_state1 {
		pkt.extract(hdr.SCTP);
		transition parse_SCTP_chunk_state1;
	}

    state parse_SCTP_chunk_state1 {
		bit<32> temp = pkt.lookahead<bit<32>>();
		transition select(temp[31:24]){
			0: parse_SCTP_chunk_data_state1;
			default: skip_SCTP_chunk;
		}
	}

	state skip_SCTP_chunk {
		bit<32> temp = pkt.lookahead<bit<32>>();
		transition select(temp[15:0]){
			0: skip_SCTP_chunk_len0;
			1: skip_SCTP_chunk_len1;
			2: skip_SCTP_chunk_len2;
			3: skip_SCTP_chunk_len3;
			4: skip_SCTP_chunk_len4;
			5: skip_SCTP_chunk_len5;
			6: skip_SCTP_chunk_len6;
			7: skip_SCTP_chunk_len7;
			8: skip_SCTP_chunk_len8;
			9: skip_SCTP_chunk_len9;
			10: skip_SCTP_chunk_len10;
			11: skip_SCTP_chunk_len11;
			12: skip_SCTP_chunk_len12;
			13: skip_SCTP_chunk_len13;
			14: skip_SCTP_chunk_len14;
			15: skip_SCTP_chunk_len15;
			16: skip_SCTP_chunk_len16;
			17: skip_SCTP_chunk_len17;
			18: skip_SCTP_chunk_len18;
			19: skip_SCTP_chunk_len19;
			20: skip_SCTP_chunk_len20;
			21: skip_SCTP_chunk_len21;
			22: skip_SCTP_chunk_len22;
			23: skip_SCTP_chunk_len23;
			24: skip_SCTP_chunk_len24;
			25: skip_SCTP_chunk_len25;
			26: skip_SCTP_chunk_len26;
			27: skip_SCTP_chunk_len27;
			28: skip_SCTP_chunk_len28;
			29: skip_SCTP_chunk_len29;
			30: skip_SCTP_chunk_len30;
			31: skip_SCTP_chunk_len31;
			32: skip_SCTP_chunk_len32;
			33: skip_SCTP_chunk_len33;
			34: skip_SCTP_chunk_len34;
			35: skip_SCTP_chunk_len35;
			36: skip_SCTP_chunk_len36;
			37: skip_SCTP_chunk_len37;
			38: skip_SCTP_chunk_len38;
			39: skip_SCTP_chunk_len39;
			40: skip_SCTP_chunk_len40;
			41: skip_SCTP_chunk_len41;
			42: skip_SCTP_chunk_len42;
			43: skip_SCTP_chunk_len43;
			44: skip_SCTP_chunk_len44;
			45: skip_SCTP_chunk_len45;
			46: skip_SCTP_chunk_len46;
			47: skip_SCTP_chunk_len47;
			48: skip_SCTP_chunk_len48;
			49: skip_SCTP_chunk_len49;
			default: accept;
		}
	}

	state skip_SCTP_chunk_len0 {pkt.advance(0);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len1 {pkt.advance(8);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len2 {pkt.advance(16);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len3 {pkt.advance(24);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len4 {pkt.advance(32);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len5 {pkt.advance(40);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len6 {pkt.advance(48);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len7 {pkt.advance(56);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len8 {pkt.advance(64);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len9 {pkt.advance(72);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len10 {pkt.advance(80);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len11 {pkt.advance(88);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len12 {pkt.advance(96);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len13 {pkt.advance(104);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len14 {pkt.advance(112);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len15 {pkt.advance(120);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len16 {pkt.advance(128);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len17 {pkt.advance(136);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len18 {pkt.advance(144);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len19 {pkt.advance(152);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len20 {pkt.advance(160);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len21 {pkt.advance(168);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len22 {pkt.advance(176);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len23 {pkt.advance(184);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len24 {pkt.advance(192);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len25 {pkt.advance(200);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len26 {pkt.advance(208);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len27 {pkt.advance(216);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len28 {pkt.advance(224);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len29 {pkt.advance(232);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len30 {pkt.advance(240);transition parse_SCTP_chunk_state1;}
	state skip_SCTP_chunk_len31 {pkt.advance(240);transition skip_SCTP_chunk_len1;}
	state skip_SCTP_chunk_len32 {pkt.advance(240);transition skip_SCTP_chunk_len2;}
	state skip_SCTP_chunk_len33 {pkt.advance(240);transition skip_SCTP_chunk_len3;}
	state skip_SCTP_chunk_len34 {pkt.advance(240);transition skip_SCTP_chunk_len4;}
	state skip_SCTP_chunk_len35 {pkt.advance(240);transition skip_SCTP_chunk_len5;}
	state skip_SCTP_chunk_len36 {pkt.advance(240);transition skip_SCTP_chunk_len6;}
	state skip_SCTP_chunk_len37 {pkt.advance(240);transition skip_SCTP_chunk_len7;}
	state skip_SCTP_chunk_len38 {pkt.advance(240);transition skip_SCTP_chunk_len8;}
	state skip_SCTP_chunk_len39 {pkt.advance(240);transition skip_SCTP_chunk_len9;}
	state skip_SCTP_chunk_len40 {pkt.advance(240);transition skip_SCTP_chunk_len10;}
	state skip_SCTP_chunk_len41 {pkt.advance(240);transition skip_SCTP_chunk_len11;}
	state skip_SCTP_chunk_len42 {pkt.advance(240);transition skip_SCTP_chunk_len12;}
	state skip_SCTP_chunk_len43 {pkt.advance(240);transition skip_SCTP_chunk_len13;}
	state skip_SCTP_chunk_len44 {pkt.advance(240);transition skip_SCTP_chunk_len14;}
	state skip_SCTP_chunk_len45 {pkt.advance(240);transition skip_SCTP_chunk_len15;}
	state skip_SCTP_chunk_len46 {pkt.advance(240);transition skip_SCTP_chunk_len16;}
	state skip_SCTP_chunk_len47 {pkt.advance(240);transition skip_SCTP_chunk_len17;}
	state skip_SCTP_chunk_len48 {pkt.advance(240);transition skip_SCTP_chunk_len18;}
	state skip_SCTP_chunk_len49 {pkt.advance(240);transition skip_SCTP_chunk_len19;}

	state parse_TLS_state1 {
		pkt.extract(hdr.TLS);
		transition select(hdr.TLS.type){
			22: parse_TLS_handshake_state1;
			default: accept;
		}
	}


	state parse_SCTP_chunk_data_state1 {
		pkt.extract(hdr.SCTP_chunk_data);
		transition select(hdr.SCTP_chunk_data.PPID){
			60: parse_NGAP_state1;
			default: accept;
		}
	}


	state parse_TLS_handshake_state1 {
		pkt.extract(hdr.TLS_handshake);
		transition select(hdr.TLS_handshake.type){
			1: parse_TLS_session_state3;
			2: parse_TLS_session_state3;
			default: accept;
		}
	}


	state parse_NGAP_state1 {
		pkt.extract(hdr.NGAP);
		transition accept;
	}


	state parse_TLS_session_state3 {
		pkt.extract(hdr.TLS_session);
		transition select(hdr.TLS_session.len[7:5]){
			0: parse_TLS_session_state2;
			1: skip_TLS_session_len32;
			2: skip_TLS_session_len64;
			3: skip_TLS_session_len96;
			default: accept;
		}
	}

	state skip_TLS_session_len32 { pkt.advance(256);transition parse_TLS_session_state2; }
	state skip_TLS_session_len64 { pkt.advance(512);transition parse_TLS_session_state2; }
	state skip_TLS_session_len96 { pkt.advance(768);transition parse_TLS_session_state2; }

	state parse_TLS_session_state2 {
		transition select(hdr.TLS_session.len[4:3]){
			0: parse_TLS_session_state1;
			1: skip_TLS_session_len8;
			2: skip_TLS_session_len16;
			3: skip_TLS_session_len24;
		}
	}

	state skip_TLS_session_len8 { pkt.advance(64);transition parse_TLS_session_state1; }
	state skip_TLS_session_len16 { pkt.advance(128);transition parse_TLS_session_state1; }
	state skip_TLS_session_len24 { pkt.advance(192);transition parse_TLS_session_state1; }

	state parse_TLS_session_state1 {
		transition select(hdr.TLS_session.len[2:0]){
			1: skip_TLS_session_len1;
			2: skip_TLS_session_len2;
			3: skip_TLS_session_len3;
			4: skip_TLS_session_len4;
			5: skip_TLS_session_len5;
			6: skip_TLS_session_len6;
			7: skip_TLS_session_len7;
			default: parse_TLS_cipher_state3;
		}
	}

	state skip_TLS_session_len1 { pkt.advance(8);transition parse_TLS_cipher_state3; }
	state skip_TLS_session_len2 { pkt.advance(16);transition parse_TLS_cipher_state3; }
	state skip_TLS_session_len3 { pkt.advance(24);transition parse_TLS_cipher_state3; }
	state skip_TLS_session_len4 { pkt.advance(32);transition parse_TLS_cipher_state3; }
	state skip_TLS_session_len5 { pkt.advance(40);transition parse_TLS_cipher_state3; }
	state skip_TLS_session_len6 { pkt.advance(48);transition parse_TLS_cipher_state3; }
	state skip_TLS_session_len7 { pkt.advance(56);transition parse_TLS_cipher_state3; }

	state parse_TLS_cipher_state3 {
		pkt.extract(hdr.TLS_cipher);
		transition select(hdr.TLS_cipher.len[15:5]){
			0: parse_TLS_cipher_state2;
			1: skip_TLS_cipher_len32;
			2: skip_TLS_cipher_len64;
			3: skip_TLS_cipher_len96;
			default: accept;
		}
	}

	state skip_TLS_cipher_len32 { pkt.advance(256);transition parse_TLS_cipher_state2; }
	state skip_TLS_cipher_len64 { pkt.advance(512);transition parse_TLS_cipher_state2; }
	state skip_TLS_cipher_len96 { pkt.advance(768);transition parse_TLS_cipher_state2; }

	state parse_TLS_cipher_state2 {
		transition select(hdr.TLS_cipher.len[4:3]){
			0: parse_TLS_cipher_state1;
			1: skip_TLS_cipher_len8;
			2: skip_TLS_cipher_len16;
			3: skip_TLS_cipher_len24;
		}
	}

	state skip_TLS_cipher_len8 { pkt.advance(64);transition parse_TLS_cipher_state1; }
	state skip_TLS_cipher_len16 { pkt.advance(128);transition parse_TLS_cipher_state1; }
	state skip_TLS_cipher_len24 { pkt.advance(192);transition parse_TLS_cipher_state1; }

	state parse_TLS_cipher_state1 {
		transition select(hdr.TLS_cipher.len[2:0]){
			1: skip_TLS_cipher_len1;
			default: parse_TLS_compression_state1;
		}
	}

	state skip_TLS_cipher_len1 { pkt.advance(8);transition parse_TLS_compression_state1; }

	state parse_TLS_compression_state1 {
		pkt.extract(hdr.TLS_compression);
		transition select(hdr.TLS_compression.len[7:0]){
			1: skip_TLS_compression_len1;
			default: accept;
		}
	}

	state skip_TLS_compression_len1 { pkt.advance(8);transition parse_TLS_extentions_len_state1; }

	state parse_TLS_extentions_len_state1 {
		pkt.extract(hdr.TLS_extentions_len);
		transition parse_TLS_extention_state1;
	}


	state parse_TLS_extention_state1 {
		bit<32> temp = pkt.lookahead<bit<32>>();
		transition select(temp[31:16]){
			0: parse_client_servername_state3;
			default: skip_TLS_extention;
		}
	}

	state skip_TLS_extention {
		bit<32> temp = pkt.lookahead<bit<32>>();
		transition select(temp[15:0]){
			0: skip_TLS_extention_len0;
			1: skip_TLS_extention_len1;
			2: skip_TLS_extention_len2;
			3: skip_TLS_extention_len3;
			4: skip_TLS_extention_len4;
			5: skip_TLS_extention_len5;
			6: skip_TLS_extention_len6;
			7: skip_TLS_extention_len7;
			8: skip_TLS_extention_len8;
			9: skip_TLS_extention_len9;
			10: skip_TLS_extention_len10;
			11: skip_TLS_extention_len11;
			12: skip_TLS_extention_len12;
			13: skip_TLS_extention_len13;
			14: skip_TLS_extention_len14;
			15: skip_TLS_extention_len15;
			16: skip_TLS_extention_len16;
			17: skip_TLS_extention_len17;
			18: skip_TLS_extention_len18;
			19: skip_TLS_extention_len19;
			20: skip_TLS_extention_len20;
			21: skip_TLS_extention_len21;
			22: skip_TLS_extention_len22;
			23: skip_TLS_extention_len23;
			24: skip_TLS_extention_len24;
			25: skip_TLS_extention_len25;
			26: skip_TLS_extention_len26;
			27: skip_TLS_extention_len27;
			28: skip_TLS_extention_len28;
			29: skip_TLS_extention_len29;
			30: skip_TLS_extention_len30;
			31: skip_TLS_extention_len31;
			32: skip_TLS_extention_len32;
			33: skip_TLS_extention_len33;
			34: skip_TLS_extention_len34;
			35: skip_TLS_extention_len35;
			36: skip_TLS_extention_len36;
			37: skip_TLS_extention_len37;
			38: skip_TLS_extention_len38;
			39: skip_TLS_extention_len39;
			40: skip_TLS_extention_len40;
			41: skip_TLS_extention_len41;
			42: skip_TLS_extention_len42;
			43: skip_TLS_extention_len43;
			44: skip_TLS_extention_len44;
			45: skip_TLS_extention_len45;
			46: skip_TLS_extention_len46;
			47: skip_TLS_extention_len47;
			48: skip_TLS_extention_len48;
			49: skip_TLS_extention_len49;
			default: accept;
		}
	}

	state skip_TLS_extention_len0 {pkt.advance(32);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len1 {pkt.advance(40);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len2 {pkt.advance(48);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len3 {pkt.advance(56);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len4 {pkt.advance(64);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len5 {pkt.advance(72);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len6 {pkt.advance(80);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len7 {pkt.advance(88);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len8 {pkt.advance(96);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len9 {pkt.advance(104);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len10 {pkt.advance(112);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len11 {pkt.advance(120);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len12 {pkt.advance(128);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len13 {pkt.advance(136);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len14 {pkt.advance(144);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len15 {pkt.advance(152);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len16 {pkt.advance(160);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len17 {pkt.advance(168);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len18 {pkt.advance(176);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len19 {pkt.advance(184);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len20 {pkt.advance(192);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len21 {pkt.advance(200);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len22 {pkt.advance(208);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len23 {pkt.advance(216);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len24 {pkt.advance(224);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len25 {pkt.advance(232);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len26 {pkt.advance(240);transition parse_TLS_extention_state1;}
	state skip_TLS_extention_len27 {pkt.advance(240);transition skip_TLS_extention_len1;}
	state skip_TLS_extention_len28 {pkt.advance(240);transition skip_TLS_extention_len2;}
	state skip_TLS_extention_len29 {pkt.advance(240);transition skip_TLS_extention_len3;}
	state skip_TLS_extention_len30 {pkt.advance(240);transition skip_TLS_extention_len4;}
	state skip_TLS_extention_len31 {pkt.advance(240);transition skip_TLS_extention_len5;}
	state skip_TLS_extention_len32 {pkt.advance(240);transition skip_TLS_extention_len6;}
	state skip_TLS_extention_len33 {pkt.advance(240);transition skip_TLS_extention_len7;}
	state skip_TLS_extention_len34 {pkt.advance(240);transition skip_TLS_extention_len8;}
	state skip_TLS_extention_len35 {pkt.advance(240);transition skip_TLS_extention_len9;}
	state skip_TLS_extention_len36 {pkt.advance(240);transition skip_TLS_extention_len10;}
	state skip_TLS_extention_len37 {pkt.advance(240);transition skip_TLS_extention_len11;}
	state skip_TLS_extention_len38 {pkt.advance(240);transition skip_TLS_extention_len12;}
	state skip_TLS_extention_len39 {pkt.advance(240);transition skip_TLS_extention_len13;}
	state skip_TLS_extention_len40 {pkt.advance(240);transition skip_TLS_extention_len14;}
	state skip_TLS_extention_len41 {pkt.advance(240);transition skip_TLS_extention_len15;}
	state skip_TLS_extention_len42 {pkt.advance(240);transition skip_TLS_extention_len16;}
	state skip_TLS_extention_len43 {pkt.advance(240);transition skip_TLS_extention_len17;}
	state skip_TLS_extention_len44 {pkt.advance(240);transition skip_TLS_extention_len18;}
	state skip_TLS_extention_len45 {pkt.advance(240);transition skip_TLS_extention_len19;}
	state skip_TLS_extention_len46 {pkt.advance(240);transition skip_TLS_extention_len20;}
	state skip_TLS_extention_len47 {pkt.advance(240);transition skip_TLS_extention_len21;}
	state skip_TLS_extention_len48 {pkt.advance(240);transition skip_TLS_extention_len22;}
	state skip_TLS_extention_len49 {pkt.advance(240);transition skip_TLS_extention_len23;}

	state parse_client_servername_state3 {
		pkt.extract(hdr.client_servername);
		transition select(hdr.client_servername.sni_len[15:5]){
			0: parse_client_servername_state2;
			1: parse_client_servername_part_32;
			default: accept;
		}

	}

	state parse_client_servername_part_32 {
		pkt.extract(hdr.client_servername_part32);
		transition accept;
	}

	state parse_client_servername_state2 {
		pkt.extract(hdr.client_servername);
		transition select(hdr.client_servername.sni_len[4:3]){
			0: parse_client_servername_state1;
			1: parse_client_servername_part_8;
			3: parse_client_servername_part_8_16;
			2: parse_client_servername_part_16;
		}

	}

	state parse_client_servername_part_8 {
		pkt.extract(hdr.client_servername_part8);
		transition accept;
	}

	state parse_client_servername_part_8_16 {
		pkt.extract(hdr.client_servername_part8);
		pkt.extract(hdr.client_servername_part16);
		transition accept;
	}

	state parse_client_servername_part_16 {
		pkt.extract(hdr.client_servername_part16);
		transition accept;
	}

	state parse_client_servername_state1 {
		pkt.extract(hdr.client_servername);
		transition select(hdr.client_servername.sni_len[2:0]){
			0: accept;
			1: parse_client_servername_part_1;
			3: parse_client_servername_part_1_2;
			2: parse_client_servername_part_2;
			7: parse_client_servername_part_1_2_4;
			6: parse_client_servername_part_2_4;
			4: parse_client_servername_part_4;
		}

	}

	state parse_client_servername_part_1 {
		pkt.extract(hdr.client_servername_part1);
		transition accept;
	}

	state parse_client_servername_part_1_2 {
		pkt.extract(hdr.client_servername_part1);
		pkt.extract(hdr.client_servername_part2);
		transition accept;
	}

	state parse_client_servername_part_2 {
		pkt.extract(hdr.client_servername_part2);
		transition accept;
	}

	state parse_client_servername_part_1_2_4 {
		pkt.extract(hdr.client_servername_part1);
		pkt.extract(hdr.client_servername_part2);
		pkt.extract(hdr.client_servername_part4);
		transition accept;
	}

	state parse_client_servername_part_2_4 {
		pkt.extract(hdr.client_servername_part2);
		pkt.extract(hdr.client_servername_part4);
		transition accept;
	}

	state parse_client_servername_part_4 {
		pkt.extract(hdr.client_servername_part4);
		transition accept;
	}
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
/***************** M A T C H - A C T I O N  *********************/
control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

//     /* Registers for flow management */
//   Register<bit<8>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_classified_flag;
//     /* Register read action */
//     RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(reg_classified_flag)
//     update_classified_flag = {
//         void apply(inout bit<8> classified_flag, out bit<8> output) {
//             if (hdr.recirc.isValid()){
//                 classified_flag = hdr.IPv4.ttl;
//             }
//             output = classified_flag;
//         }
//     };

    /* Register for number of observed packets per flow */
    Register<bit<8>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) flow_pkt_count_reg;
    /* Register read action */
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(flow_pkt_count_reg)
    get_update_flow_pkt_count_reg = {
        void apply(inout bit<8> pkt_count, out bit<8> output) {
            output = pkt_count;
            pkt_count = pkt_count + 1;
        }
    };

    /* Register to set length of packet 0 */
    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) flow_pkt_length_0_reg;
    /* Register set action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_0_reg)
    set_flow_pkt_length_0 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            pkt_length = hdr.TLS.len;
        }
    };
    /* Register get action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_0_reg)
    get_flow_pkt_length_0 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            output = pkt_length;
        }
    };

    /* Register to set length of packet 1 */
    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) flow_pkt_length_1_reg;
    /* Register set action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_1_reg)
    set_flow_pkt_length_1 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            pkt_length = hdr.TLS.len;
        }
    };
    /* Register get action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_1_reg)
    get_flow_pkt_length_1 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            output = pkt_length;
        }
    };

    /* Register to set length of packet 2 */
    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) flow_pkt_length_2_reg;
    /* Register set action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_2_reg)
    set_flow_pkt_length_2 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            pkt_length = hdr.TLS.len;
        }
    };
    /* Register get action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_2_reg)
    get_flow_pkt_length_2 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            output = pkt_length;
        }
    };

    /* Register to set length of packet 3 */
    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) flow_pkt_length_3_reg;
    /* Register set action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_3_reg)
    set_flow_pkt_length_3 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            pkt_length = hdr.TLS.len;
        }
    };
    /* Register get action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_3_reg)
    get_flow_pkt_length_3 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            output = pkt_length;
        }
    };

    /* Register to set length of packet 4 */
    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) flow_pkt_length_4_reg;
    /* Register set action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_4_reg)
    set_flow_pkt_length_4 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            pkt_length = hdr.TLS.len;
        }
    };
    /* Register get action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_4_reg)
    get_flow_pkt_length_4 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            output = pkt_length;
        }
    };

    /* Register to set length of packet 5 */
    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) flow_pkt_length_5_reg;
    /* Register set action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_5_reg)
    set_flow_pkt_length_5 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            pkt_length = hdr.TLS.len;
        }
    };
    /* Register get action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_5_reg)
    get_flow_pkt_length_5 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            output = pkt_length;
        }
    };

    /* Register to set length of packet 6 */
    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) flow_pkt_length_6_reg;
    /* Register set action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_6_reg)
    set_flow_pkt_length_6 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            pkt_length = hdr.TLS.len;
            output = pkt_length;
        }
    };
    /* Register get action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_6_reg)
    get_flow_pkt_length_6 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
        }
    };

    /* Register to set length of packet 7 */
    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) flow_pkt_length_7_reg;
    /* Register set action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_7_reg)
    set_flow_pkt_length_7 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            pkt_length = hdr.TLS.len;
        }
    };
    /* Register get action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_7_reg)
    get_flow_pkt_length_7 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            output = pkt_length;
        }
    };

    /* Register to set length of packet 8 */
    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) flow_pkt_length_8_reg;
    /* Register set action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_8_reg)
    set_flow_pkt_length_8 = {
        void apply(inout bit<16> pkt_length) {
            pkt_length = hdr.TLS.len;
        }
    };
    /* Register get action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_8_reg)
    get_flow_pkt_length_8 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            output = pkt_length;
        }
    };

    /* Register to set length of packet 9 */
    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) flow_pkt_length_9_reg;
    /* Register set action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_9_reg)
    set_flow_pkt_length_9 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            pkt_length = hdr.TLS.len;
        }
    };
    /* Register get action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_9_reg)
    get_flow_pkt_length_9 = {
        void apply(inout bit<16> pkt_length, out bit<16> output) {
            output = pkt_length;
        }
    };


    /* Register to store the status of a flow (i.e., if the flow is still under examination) */
    Register<bit<1>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) reg_status;
    /* Register read action */
    RegisterAction<bit<1>,bit<(INDEX_WIDTH)>,bit<1>>(reg_status)
    read_reg_status = {
        void apply(inout bit<1> status, out bit<1> output) {
            output = status;
            status = 1;
        }
    };

    /* Register to store the directions of the flows */
    Register<bit<(16)>,bit<16>>(MAX_REGISTER_ENTRIES) flow_dir_reg;
    /* Register set action for c2s*/
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_dir_reg)
    set_flow_dir_reg = {
        void apply(inout bit<16> register_index, out bit<16> output) {
            register_index = (bit<16>)meta.flow_ID;
        }
    };
    /* Register set action for s2c*/
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_dir_reg)
    set_rev_flow_dir_reg = {
        void apply(inout bit<16> register_index, out bit<16> output) {
            register_index = (bit<16>)meta.flow_ID;
        }
    };
    /* Register read action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_dir_reg)
    read_flow_dir_reg = {
        void apply(inout bit<16> register_index, out bit<16> output) {
           output = register_index;
        }
    };
    action get_register_index(){
        meta.register_index = (bit<(INDEX_WIDTH)>)read_flow_dir_reg.execute((bit<16>)meta.flow_ID);
    }


    /* Declaration of the hashes*/
    Hash<bit<(INDEX_WIDTH)>>(HashAlgorithm_t.CRC16)     flow_id_calc;
    Hash<bit<(INDEX_WIDTH)>>(HashAlgorithm_t.CRC16)     rev_flow_id_calc;

    /* Calculate hash of the 5-tuple to represent the flow ID */
    action get_flow_ID() {
        meta.flow_ID = flow_id_calc.get({hdr.IPv4.src_addr, hdr.IPv4.dst_addr,hdr.TCP.src_port, hdr.TCP.dst_port, hdr.IPv4.protocol});
    }
    /* Calculate hash of the reversed 5-tuple to represent the reversed flow ID */
    action get_rev_flow_ID() {
        meta.rev_flow_ID = rev_flow_id_calc.get({hdr.IPv4.src_addr, hdr.IPv4.dst_addr,hdr.TCP.dst_port, hdr.TCP.src_port, hdr.IPv4.protocol});
    }

    /* Assign class if at leaf node */
    action SetClass0(bit<8> classe) {
        meta.class0 = classe;
    }
    action SetClass1(bit<8> classe) {
        meta.class1 = classe;
    }
    action SetClass2(bit<8> classe) {
        meta.class2 = classe;
    }
    action SetClass3(bit<8> classe) {
        meta.class3 = classe;
    }
    action SetClass4(bit<8> classe) {
        meta.class4 = classe;
    }

    /* Forward to a specific port upon classification */
    action ipv4_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    /* Custom Do Nothing Action */
    action nop(){}

    /* Feature table actions */
    action SetCode0(bit<91> code0, bit<106> code1, bit<94> code2, bit<78> code3, bit<88> code4) {
        meta.codeword0[307:217] = code0;
        meta.codeword1[357:252] = code1;
        meta.codeword2[304:211] = code2;
        meta.codeword3[317:240] = code3;
        meta.codeword4[324:237] = code4;
    }
    action SetCode1(bit<19> code0, bit<25> code1, bit<26> code2, bit<29> code3, bit<29> code4)  {
        meta.codeword0[216:198] = code0;
        meta.codeword1[251:227] = code1;
        meta.codeword2[210:185] = code2;
        meta.codeword3[239:211] = code3;
        meta.codeword4[236:208] = code4;
    }
    action SetCode2(bit<97> code0, bit<105> code1, bit<84> code2, bit<83> code3, bit<99> code4)  {
        meta.codeword0[197:101] = code0;
        meta.codeword1[226:122] = code1;
        meta.codeword2[184:101] = code2;
        meta.codeword3[210:128] = code3;
        meta.codeword4[207:109] = code4;
    }
    action SetCode3(bit<16> code0, bit<16> code1, bit<8> code2, bit<17> code3, bit<15> code4)  { //gere
        meta.codeword0[100:85]  = code0;
        meta.codeword1[121:106]  = code1;
        meta.codeword2[100:93]  = code2;
        meta.codeword3[127:111]  = code3;
        meta.codeword4[108:94]  = code4;
    }
    action SetCode4(bit<9> code0, bit<7> code1, bit<13> code2, bit<10> code3, bit<6> code4) {
        meta.codeword0[84:76]  = code0;
        meta.codeword1[105:99]  = code1;
        meta.codeword2[92:80]  = code2;
        meta.codeword3[110:101]  = code3;
        meta.codeword4[93:88]  = code4;
    }
    action SetCode5(bit<4> code0, bit<12> code1, bit<9> code2, bit<12> code3, bit<8> code4)  {
        meta.codeword0[75:72]  = code0;
        meta.codeword1[98:87]  = code1;
        meta.codeword2[79:71]  = code2;
        meta.codeword3[100:89]  = code3;
        meta.codeword4[87:80]  = code4;
    }
    action SetCode6(bit<7> code0, bit<6> code1, bit<6> code2, bit<13> code3, bit<9> code4)  {
        meta.codeword0[71:65]  = code0;
        meta.codeword1[86:81]  = code1;
        meta.codeword2[70:65]  = code2;
        meta.codeword3[88:76]  = code3;
        meta.codeword4[79:71]  = code4;
    }
    action SetCode7(bit<9> code0, bit<11> code1, bit<13> code2, bit<11> code3, bit<15> code4)  {
        meta.codeword0[64:56]  = code0;
        meta.codeword1[80:70]  = code1;
        meta.codeword2[64:52]  = code2;
        meta.codeword3[75:65]  = code3;
        meta.codeword4[70:56]  = code4;
    }
    action SetCode8(bit<17> code0, bit<20> code1, bit<14> code2, bit<21> code3, bit<18> code4)  {
        meta.codeword0[55:39]  = code0;
        meta.codeword1[69:50]  = code1;
        meta.codeword2[51:38]  = code2;
        meta.codeword3[64:44]  = code3;
        meta.codeword4[55:38]  = code4;
    }
    action SetCode9(bit<39> code0, bit<50> code1, bit<38> code2, bit<44> code3, bit<38> code4)  {
        meta.codeword0[38:0]  = code0;
        meta.codeword1[49:0]  = code1;
        meta.codeword2[37:0]  = code2;
        meta.codeword3[43:0]  = code3;
        meta.codeword4[37:0]  = code4;
    }

    /* Feature tables */
    table table_feature0{
	    key = {meta.pkt_len_0: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 111;
        const default_action = nop();
	}
    table table_feature1{
        key = {meta.pkt_len_1: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 49;
        const default_action = nop();
	}
	table table_feature2{
        key = {meta.pkt_len_2: range @name("feature2");} 
	    actions = {@defaultonly nop; SetCode2;}
	    size = 192;
        const default_action = nop();
	}
    table table_feature3{
	    key = {meta.pkt_len_3: range @name("feature3");}
	    actions = {@defaultonly nop; SetCode3;}
	    size = 40;
        const default_action = nop();
	}
    table table_feature4{
	    key = {meta.pkt_len_4: range @name("feature4");}
	    actions = {@defaultonly nop; SetCode4;}
	    size = 27;
        const default_action = nop();
	}
    table table_feature5{
	    key = {meta.pkt_len_5: range @name("feature5");}
	    actions = {@defaultonly nop; SetCode5;}
	    size = 25;
        const default_action = nop();
	}
    table table_feature6{
	    key = {meta.pkt_len_6: range @name("feature6");}
	    actions = {@defaultonly nop; SetCode6;}
	    size = 30;
        const default_action = nop();
	}
    table table_feature7{
	    key = {meta.pkt_len_7: range @name("feature7");}
	    actions = {@defaultonly nop; SetCode7;}
	    size = 36;
        const default_action = nop();
	}
    table table_feature8{
	    key = {meta.pkt_len_8: range @name("feature8");}
	    actions = {@defaultonly nop; SetCode8;}
	    size = 55;
        const default_action = nop();
	}
    table table_feature9{
	    key = {meta.pkt_len_9: range @name("feature9");}
	    actions = {@defaultonly nop; SetCode9;}
	    size = 88;
        const default_action = nop();
	}

    /* Code tables */
	table code_table0{
	    key = {meta.codeword0: ternary;}
	    actions = {@defaultonly nop; SetClass0;}
	    size = 309;
        const default_action = nop();
	}
	table code_table1{
        key = {meta.codeword1: ternary;}
	    actions = {@defaultonly nop; SetClass1;}
	    size = 370;
        const default_action = nop();
	}
	table code_table2{
        key = {meta.codeword2: ternary;}
	    actions = {@defaultonly nop; SetClass2;}
	    size = 359;
        const default_action = nop();
	}
	table code_table3{
        key = {meta.codeword3: ternary;}
	    actions = {@defaultonly nop; SetClass3;}
	    size = 319;
        const default_action = nop();
	}
	table code_table4{
        key = {meta.codeword4: ternary;}
	    actions = {@defaultonly nop; SetClass4;}
	    size = 326;
        const default_action = nop();
	}

    action set_default_result() {
        meta.final_class = meta.class0;
    }

    action set_final_class(bit<8> class_result) {
        meta.final_class = class_result;
    }

    table voting_table {
        key = {
            meta.class0: exact;
            meta.class1: exact;
            meta.class2: exact;
            meta.class3: exact;
            meta.class4: exact;
        }
        actions = {set_final_class; @defaultonly set_default_result;}
        size = 32;
        const default_action = set_default_result();
    }

    /* Forwarding-Inference Block Table */
    action set_flow_class(bit<8> f_class) {
        meta.final_class = f_class;
    }
    /* Class of type 2 means that the flow is not classified */
    action set_default_fow_class() {
        meta.final_class = 2;
    }

    table target_flows_table {
        key = {
            hdr.IPv4.src_addr: exact;
            hdr.IPv4.dst_addr: exact;
            hdr.TCP.src_port: exact;
            hdr.TCP.dst_port: exact;
            hdr.IPv4.protocol: exact;
        }
        actions = {set_flow_class; @defaultonly set_default_fow_class;}
        size = 500;
        const default_action = set_default_fow_class();
    }

    apply {
            // filter for background or already classified traffic
            // target_flows_table.apply();

            // get flow ID and register index
            

            // read_flow_dir_reg.execute(meta.flow_ID);

            get_flow_ID();
            
            if(hdr.TLS_handshake.isValid()){
                get_rev_flow_ID();
                set_flow_dir_reg.execute(meta.flow_ID);
                set_rev_flow_dir_reg.execute(meta.rev_flow_ID);
                meta.pkt_count = get_update_flow_pkt_count_reg.execute(meta.flow_ID);

            }
            else if(hdr.TLS.isValid()){
                get_register_index();
                meta.pkt_count = get_update_flow_pkt_count_reg.execute(meta.register_index);

                if(meta.pkt_count < 9){
                    if(meta.pkt_count < 5){
                        if(meta.pkt_count == 0){
                            set_flow_pkt_length_0.execute(meta.register_index);
                        }
                        
                        if(meta.pkt_count == 1){
                            set_flow_pkt_length_1.execute(meta.register_index);
                        }
                        
                        if(meta.pkt_count == 2){
                            set_flow_pkt_length_2.execute(meta.register_index);
                        }
                        
                        if(meta.pkt_count == 3){
                            set_flow_pkt_length_3.execute(meta.register_index);
                        }
                        
                        else{
                            set_flow_pkt_length_4.execute(meta.register_index);
                        }
                    }
                    else{
                        if(meta.pkt_count == 5){
                            set_flow_pkt_length_5.execute(meta.register_index);
                        }
                        
                        if(meta.pkt_count == 6){
                            set_flow_pkt_length_6.execute(meta.register_index);
                        }
                        
                        if(meta.pkt_count == 7){
                            set_flow_pkt_length_7.execute(meta.register_index);
                        }

                        if(meta.pkt_count == 8){
                            set_flow_pkt_length_8.execute(meta.register_index);
                        }
                    }
                }

                // check if # of packets requirement is met
                else if(meta.pkt_count == 9){

                    // meta.pkt_len_0 = get_flow_pkt_length_0.execute(meta.register_index);
                    // meta.pkt_len_1 = get_flow_pkt_length_1.execute(meta.register_index);
                    // meta.pkt_len_2 = get_flow_pkt_length_2.execute(meta.register_index);
                    // meta.pkt_len_3 = get_flow_pkt_length_3.execute(meta.register_index);
                    // meta.pkt_len_4 = get_flow_pkt_length_4.execute(meta.register_index);
                    // meta.pkt_len_5 = get_flow_pkt_length_5.execute(meta.register_index);
                    // meta.pkt_len_6 = get_flow_pkt_length_6.execute(meta.register_index);
                    // meta.pkt_len_7 = get_flow_pkt_length_7.execute(meta.register_index);
                    // meta.pkt_len_8 = get_flow_pkt_length_8.execute(meta.register_index);
                    // meta.pkt_len_9 = hdr.TLS.len;

                    hdr.packet_lengths.setValid();

                    hdr.packet_lengths.pkt_len_0 = get_flow_pkt_length_0.execute(meta.register_index);
                    hdr.packet_lengths.pkt_len_1 = get_flow_pkt_length_1.execute(meta.register_index);
                    hdr.packet_lengths.pkt_len_2 = get_flow_pkt_length_2.execute(meta.register_index);
                    hdr.packet_lengths.pkt_len_3 = get_flow_pkt_length_3.execute(meta.register_index);
                    hdr.packet_lengths.pkt_len_4 = get_flow_pkt_length_4.execute(meta.register_index);
                    hdr.packet_lengths.pkt_len_5 = get_flow_pkt_length_5.execute(meta.register_index);
                    hdr.packet_lengths.pkt_len_6 = get_flow_pkt_length_6.execute(meta.register_index);
                    hdr.packet_lengths.pkt_len_7 = get_flow_pkt_length_7.execute(meta.register_index);
                    hdr.packet_lengths.pkt_len_8 = get_flow_pkt_length_8.execute(meta.register_index);
                    hdr.packet_lengths.pkt_len_9 = hdr.TLS.len;

                    // // apply feature tables to assign codes
                    //     table_feature0.apply();
                    //     table_feature1.apply();
                    //     table_feature2.apply();
                    //     table_feature3.apply();
                    //     table_feature4.apply();
                    //     table_feature5.apply();
                    //     table_feature6.apply();
                    //     table_feature7.apply();
                    //     table_feature8.apply();
                    //     table_feature9.apply();                        

                    // // apply code tables to assign labels
                    //     code_table0.apply();
                    //     code_table1.apply();
                    //     code_table2.apply();
                    //     code_table3.apply();
                    //     code_table4.apply();

                    // // decide final class
                    // voting_table.apply();
                }                    
            }
            ipv4_forward(260);
    } //END OF APPLY
} //END OF INGRESS CONTROL

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Digest<flow_class_digest>() digest;

    apply {

        /* we do not update checksum because we used ttl field for stats*/
        pkt.emit(hdr);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
struct my_egress_headers_t {

    Ethernet_h Ethernet;
    recirc_h     recirc;
    packet_lengths_h packet_lengths;
	IPv4_h IPv4;
	TCP_h TCP;
	TCP_after_h TCP_after;
	TCP_options_h TCP_options;
	TLS_h TLS;
	TLS_handshake_h TLS_handshake;
	TLS_session_h TLS_session;
	TLS_cipher_h TLS_cipher;
	TLS_compression_h TLS_compression;
	TLS_extentions_len_h TLS_extentions_len;
	TLS_extention_h TLS_extention;
	client_servername_h client_servername;
	client_servername_part1_h client_servername_part1;
	client_servername_part2_h client_servername_part2;
	client_servername_part4_h client_servername_part4;
	client_servername_part8_h client_servername_part8;
	client_servername_part16_h client_servername_part16;
	client_servername_part32_h client_servername_part32;
	SCTP_h SCTP;
	SCTP_chunk_h SCTP_chunk;
	SCTP_chunk_data_h SCTP_chunk_data;
	NGAP_h NGAP;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    bit<8> classified_flag;

    bit<1>  reg_status;
    bit<(INDEX_WIDTH)> flow_ID;
    bit<(INDEX_WIDTH)> rev_flow_ID;
    bit<(INDEX_WIDTH)> register_index;

    bit<1> direction;

    bit<8> pkt_count;

    bit<16> pkt_len_0;
    bit<16> pkt_len_1;
    bit<16> pkt_len_2;
    bit<16> pkt_len_3;
    bit<16> pkt_len_4;
    bit<16> pkt_len_5;
    bit<16> pkt_len_6;
    bit<16> pkt_len_7;
    bit<16> pkt_len_8;
    bit<16> pkt_len_9;

    bit<8> class0;
    bit<8> class1;
    bit<8> class2;
    bit<8> class3;
    bit<8> class4;
    
    bit<8> final_class;

    bit<308> codeword0;
    bit<358> codeword1;
    bit<305> codeword2;
    bit<318> codeword3;
    bit<325> codeword4;
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.Ethernet);
        transition select(hdr.Ethernet.ether_type) {
            TYPE_IPV4:  parse_ipv4;
            123: parse_packet_lengths;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.IPv4);
        meta.final_class=10;
        transition select(hdr.IPv4.protocol){
			default: accept;
		}
    }

    state parse_packet_lengths{
        pkt.extract(hdr.packet_lengths);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{


    /* Assign class if at leaf node */
    action SetClass0(bit<8> classe) {
        meta.class0 = classe;
    }
    action SetClass1(bit<8> classe) {
        meta.class1 = classe;
    }
    action SetClass2(bit<8> classe) {
        meta.class2 = classe;
    }
    action SetClass3(bit<8> classe) {
        meta.class3 = classe;
    }
    action SetClass4(bit<8> classe) {
        meta.class4 = classe;
    }

    /* Custom Do Nothing Action */
    action nop(){}

    /* Feature table actions */
    action SetCode0(bit<91> code0, bit<106> code1, bit<94> code2, bit<78> code3, bit<88> code4) {
        meta.codeword0[307:217] = code0;
        meta.codeword1[357:252] = code1;
        meta.codeword2[304:211] = code2;
        meta.codeword3[317:240] = code3;
        meta.codeword4[324:237] = code4;
    }
    action SetCode1(bit<19> code0, bit<25> code1, bit<26> code2, bit<29> code3, bit<29> code4)  {
        meta.codeword0[216:198] = code0;
        meta.codeword1[251:227] = code1;
        meta.codeword2[210:185] = code2;
        meta.codeword3[239:211] = code3;
        meta.codeword4[236:208] = code4;
    }
    action SetCode2(bit<97> code0, bit<105> code1, bit<84> code2, bit<83> code3, bit<99> code4)  {
        meta.codeword0[197:101] = code0;
        meta.codeword1[226:122] = code1;
        meta.codeword2[184:101] = code2;
        meta.codeword3[210:128] = code3;
        meta.codeword4[207:109] = code4;
    }
    action SetCode3(bit<16> code0, bit<16> code1, bit<8> code2, bit<17> code3, bit<15> code4)  { //gere
        meta.codeword0[100:85]  = code0;
        meta.codeword1[121:106]  = code1;
        meta.codeword2[100:93]  = code2;
        meta.codeword3[127:111]  = code3;
        meta.codeword4[108:94]  = code4;
    }
    action SetCode4(bit<9> code0, bit<7> code1, bit<13> code2, bit<10> code3, bit<6> code4) {
        meta.codeword0[84:76]  = code0;
        meta.codeword1[105:99]  = code1;
        meta.codeword2[92:80]  = code2;
        meta.codeword3[110:101]  = code3;
        meta.codeword4[93:88]  = code4;
    }
    action SetCode5(bit<4> code0, bit<12> code1, bit<9> code2, bit<12> code3, bit<8> code4)  {
        meta.codeword0[75:72]  = code0;
        meta.codeword1[98:87]  = code1;
        meta.codeword2[79:71]  = code2;
        meta.codeword3[100:89]  = code3;
        meta.codeword4[87:80]  = code4;
    }
    action SetCode6(bit<7> code0, bit<6> code1, bit<6> code2, bit<13> code3, bit<9> code4)  {
        meta.codeword0[71:65]  = code0;
        meta.codeword1[86:81]  = code1;
        meta.codeword2[70:65]  = code2;
        meta.codeword3[88:76]  = code3;
        meta.codeword4[79:71]  = code4;
    }
    action SetCode7(bit<9> code0, bit<11> code1, bit<13> code2, bit<11> code3, bit<15> code4)  {
        meta.codeword0[64:56]  = code0;
        meta.codeword1[80:70]  = code1;
        meta.codeword2[64:52]  = code2;
        meta.codeword3[75:65]  = code3;
        meta.codeword4[70:56]  = code4;
    }
    action SetCode8(bit<17> code0, bit<20> code1, bit<14> code2, bit<21> code3, bit<18> code4)  {
        meta.codeword0[55:39]  = code0;
        meta.codeword1[69:50]  = code1;
        meta.codeword2[51:38]  = code2;
        meta.codeword3[64:44]  = code3;
        meta.codeword4[55:38]  = code4;
    }
    action SetCode9(bit<39> code0, bit<50> code1, bit<38> code2, bit<44> code3, bit<38> code4)  {
        meta.codeword0[38:0]  = code0;
        meta.codeword1[49:0]  = code1;
        meta.codeword2[37:0]  = code2;
        meta.codeword3[43:0]  = code3;
        meta.codeword4[37:0]  = code4;
    }

    /* Feature tables */
    table table_feature0{
	    key = {hdr.packet_lengths.pkt_len_0: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 111;
        const default_action = nop();
	}
    table table_feature1{
        key = {hdr.packet_lengths.pkt_len_1: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 49;
        const default_action = nop();
	}
	table table_feature2{
        key = {hdr.packet_lengths.pkt_len_2: range @name("feature2");} 
	    actions = {@defaultonly nop; SetCode2;}
	    size = 192;
        const default_action = nop();
	}
    table table_feature3{
	    key = {hdr.packet_lengths.pkt_len_3: range @name("feature3");}
	    actions = {@defaultonly nop; SetCode3;}
	    size = 40;
        const default_action = nop();
	}
    table table_feature4{
	    key = {hdr.packet_lengths.pkt_len_4: range @name("feature4");}
	    actions = {@defaultonly nop; SetCode4;}
	    size = 27;
        const default_action = nop();
	}
    table table_feature5{
	    key = {hdr.packet_lengths.pkt_len_5: range @name("feature5");}
	    actions = {@defaultonly nop; SetCode5;}
	    size = 25;
        const default_action = nop();
	}
    table table_feature6{
	    key = {hdr.packet_lengths.pkt_len_6: range @name("feature6");}
	    actions = {@defaultonly nop; SetCode6;}
	    size = 30;
        const default_action = nop();
	}
    table table_feature7{
	    key = {hdr.packet_lengths.pkt_len_7: range @name("feature7");}
	    actions = {@defaultonly nop; SetCode7;}
	    size = 36;
        const default_action = nop();
	}
    table table_feature8{
	    key = {hdr.packet_lengths.pkt_len_8: range @name("feature8");}
	    actions = {@defaultonly nop; SetCode8;}
	    size = 55;
        const default_action = nop();
	}
    table table_feature9{
	    key = {hdr.packet_lengths.pkt_len_9: range @name("feature9");}
	    actions = {@defaultonly nop; SetCode9;}
	    size = 88;
        const default_action = nop();
	}

    /* Code tables */
	table code_table0{
	    key = {meta.codeword0: ternary;}
	    actions = {@defaultonly nop; SetClass0;}
	    size = 309;
        const default_action = nop();
	}
	table code_table1{
        key = {meta.codeword1: ternary;}
	    actions = {@defaultonly nop; SetClass1;}
	    size = 370;
        const default_action = nop();
	}
	table code_table2{
        key = {meta.codeword2: ternary;}
	    actions = {@defaultonly nop; SetClass2;}
	    size = 359;
        const default_action = nop();
	}
	table code_table3{
        key = {meta.codeword3: ternary;}
	    actions = {@defaultonly nop; SetClass3;}
	    size = 319;
        const default_action = nop();
	}
	table code_table4{
        key = {meta.codeword4: ternary;}
	    actions = {@defaultonly nop; SetClass4;}
	    size = 326;
        const default_action = nop();
	}

    action set_default_result() {
        meta.final_class = meta.class0;
    }

    action set_final_class(bit<8> class_result) {
        meta.final_class = class_result;
    }

    table voting_table {
        key = {
            meta.class0: exact;
            meta.class1: exact;
            meta.class2: exact;
            meta.class3: exact;
            meta.class4: exact;
        }
        actions = {set_final_class; @defaultonly set_default_result;}
        size = 32;
        const default_action = set_default_result();
    }

    apply {
        if(hdr.packet_lengths.isValid()){
            // apply feature tables to assign codes
                table_feature0.apply();
                table_feature1.apply();
                table_feature2.apply();
                table_feature3.apply();
                table_feature4.apply();
                table_feature5.apply();
                table_feature6.apply();
                table_feature7.apply();
                table_feature8.apply();
                table_feature9.apply();                        

            // apply code tables to assign labels
                code_table0.apply();
                code_table1.apply();
                code_table2.apply();
                code_table3.apply();
                code_table4.apply();

            // decide final class
            voting_table.apply();

            if(meta.final_class == 1){
                // drop();
                eg_dprsr_md.drop_ctl = 1;
            }
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;