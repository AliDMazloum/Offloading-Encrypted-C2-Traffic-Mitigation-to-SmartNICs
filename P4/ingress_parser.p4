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

struct my_ingress_headers_t {
	Ethernet_h Ethernet;
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

}

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
struct my_ingress_metadata_t {

}

/***********************  E G R E S S  H E A D E R S  ***************************/

struct my_egress_headers_t {

}

/********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

parser IngressParser(packet_in pkt,out my_ingress_headers_t hdr,
    out my_ingress_metadata_t meta, out ingress_intrinsic_metadata_t  ig_intr_md)
{
    state start {
            pkt.extract(ig_intr_md);
            pkt.advance(PORT_METADATA_SIZE);
            transition parse_Ethernet_state1;
        }

	state parse_Ethernet_state1 {
		pkt.extract(hdr.Ethernet);
		transition select(hdr.Ethernet.ether_type){
			2048: parse_IPv4_state1;
			default: accept;
		}
	}


	state parse_IPv4_state1 {
		pkt.extract(hdr.IPv4);
		transition select(hdr.IPv4.protocol){
			6: parse_TCP_state1;
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

	state parse_TLS_state1 {
		pkt.extract(hdr.TLS);
		transition select(hdr.TLS.type){
			22: parse_TLS_handshake_state1;
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
