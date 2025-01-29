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
const bit<32>       MAX_REGISTER_ENTRIES = 2048;
#define INDEX_WIDTH 16
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

header Ethernet_h {
	bit<48> dst_addr;
	bit<48> src_add;
	bit<16> ether_type;
}

header ipv4_h {
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

header TLS_client_hello_h {
	bit<8> type;
	bit<24> len;
	bit<16> version;
}

header TLS_server_hello_h {
	bit<8> type;
	bit<24> len;
	bit<16> version;
}

header TLS_certificate_h {
	bit<8> type;
	bit<24> len;
	bit<16> version;
}

header TLS_server_key_exchange_h {
	bit<8> type;
	bit<24> len;
	bit<16> version;
}

header TLS_server_hello_done_h {
	bit<8> type;
	bit<24> len;
	bit<16> version;
}

header TLS_client_key_exchange_h {
	bit<8> type;
	bit<24> len;
	bit<16> version;
}

header TLS_encrypted_handshake_message_h {
	bit<8> type;
	bit<24> len;
	bit<16> version;
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

struct flow_class_digest {  // maximum size allowed is 47 bytes
    
    ipv4_addr_t  source_addr;   // 32 bits
    ipv4_addr_t  destin_addr;   // 32 bits
    bit<16> source_port;
    bit<16> destin_port;
    bit<8> protocol;
    bit<8> class_value;
    bit<8> packet_num;
    bit<(INDEX_WIDTH)> register_index;
}

struct pkt_lengths_digest {  // maximum size allowed is 47 bytes
    
    bit<16> pkt_len_0;
    bit<16> pkt_len_1;
    bit<16> pkt_len_2;
    bit<16> pkt_len_3;
    bit<16> pkt_len_4;
    bit<16> pkt_len_5;
    // bit<16> pkt_len_6;
    // bit<16> pkt_len_7;
    // bit<16> pkt_len_8;
    // bit<16> pkt_len_9;
    
}

struct detected_flow_digest {  // maximum size allowed is 47 bytes
    
    bit<16> flow_id;
    bit<16> rev_flow_id;
    
}

/***********************  H E A D E R S  ************************/
struct my_ingress_headers_t {
    Ethernet_h ethernet;
    recirc_h     recirc;
    packet_lengths_h packet_lengths;
	ipv4_h ipv4;
	TCP_h tcp;
	TCP_after_h TCP_after;
	TCP_options_h TCP_options;
	TLS_h TLS;
    TLS_h TLS_1;
    TLS_h TLS_2;
    TLS_h TLS_3;
    // TLS_handshake_h TLS_handshake;
}

/* Register to set length of packet (num) */
#define flow_pkt_length_reg_(num)    Register<bit<16>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) flow_pkt_length_##num;\
    /* Register set action */\
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_##num)\
    set_flow_pkt_length_##num = {\
        void apply(inout bit<16> pkt_length) {\
            pkt_length = hdr.TLS.len;\
        }\
    };\
    /* Register get action */\
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_pkt_length_##num)\
    get_flow_pkt_length_##num = {\
        void apply(inout bit<16> pkt_length, out bit<16> output) {\
            output = pkt_length;\
        }\
    }\

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
struct my_ingress_metadata_t {
    bit<8> classified_flag;

    bit<1>  reg_status;
    bit<(INDEX_WIDTH)> flow_ID;
    bit<(INDEX_WIDTH)> rev_flow_ID;
    bit<(INDEX_WIDTH)> register_index;

    bit<1> direction;

    bit<8> pkt_count;
    
    bit<8> final_class;

    MirrorId_t ing_mir_ses;   // Ingress mirror session ID
    pkt_type_t pkt_type;

    bit<8> TLS_records;


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
            1 : reject;
            0 : parse_port_metadata;
        }
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
    ParserCounter() counter;

    TofinoIngressParser() tofino_parser;

    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        meta.pkt_count =1;
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
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
        meta.pkt_count =meta.pkt_count+1;
        pkt.extract(hdr.ipv4);
        meta.final_class=10;
        transition select(hdr.ipv4.protocol){
			6: parse_TCP_state1;
			default: accept;
		}
    }

    state parse_TCP_state1 {
        pkt.extract(hdr.tcp);
		transition select(hdr.tcp.data_offset){
			5: parse_TCP_after_state1;
			8: parse_TCP_options_state1;
			default: accept;
		}
    }

    state parse_TCP_after_state1 {
		pkt.extract(hdr.TCP_after);
		transition select(hdr.tcp.dst_port){
			443: parse_TLS_state1;
			default: accept;
		}
	}


	state parse_TCP_options_state1 {
		pkt.extract(hdr.TCP_options);
		transition select(hdr.tcp.dst_port){
			443: parse_TLS_state1;
			default: accept;
		}
	}

	state parse_TLS_state1 {
		pkt.extract(hdr.TLS);
        meta.TLS_records = 1;
		transition select(hdr.TLS.type){
			// 22: parse_TLS_handshake_state1;
			default: accept;
		}
	}


	// state parse_TLS_handshake_state1 {
	// 	pkt.extract(hdr.TLS_handshake);
	// 	transition select(hdr.TLS_handshake.type){
	// 		default: accept;
	// 	}
	// }
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

    action recirculate(bit<7> recirc_port) {
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
        ig_tm_md.ucast_egress_port[6:0] = recirc_port;
        hdr.recirc.setValid();
        // hdr.recirc.class_result = meta.final_class;
        hdr.ethernet.ether_type = TYPE_RECIRC;
    }

    /* Register for number of observed packets per flow */
    Register<bit<8>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) flow_pkt_count_reg;
    /* Register set action */
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(flow_pkt_count_reg)
    set_flow_pkt_count_reg = {
        void apply(inout bit<8> pkt_count) {
            pkt_count = 1;
        }
    };
    /* Register read action */
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<8>>(flow_pkt_count_reg)
    get_update_flow_pkt_count_reg = {
        void apply(inout bit<8> pkt_count, out bit<8> output) {
            output = pkt_count;
            pkt_count = pkt_count + 1;
        }
    };

    /* Register to maintain the lengths of the first 10 packets 0 */
    flow_pkt_length_reg_(0);
    flow_pkt_length_reg_(1);
    flow_pkt_length_reg_(2);
    flow_pkt_length_reg_(3);
    flow_pkt_length_reg_(4);
    flow_pkt_length_reg_(5);
    flow_pkt_length_reg_(6);
    flow_pkt_length_reg_(7);
    flow_pkt_length_reg_(8);
    flow_pkt_length_reg_(9);


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
        void apply(inout bit<16> register_index) {
            register_index = meta.flow_ID;
        }
    };
    /* Register set action for s2c*/
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_dir_reg)
    set_rev_flow_dir_reg = {
        void apply(inout bit<16> register_index) {
            register_index = meta.flow_ID;
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
        meta.register_index = read_flow_dir_reg.execute(meta.flow_ID);
    }


    /* Declaration of the hashes*/
    Hash<bit<(INDEX_WIDTH)>>(HashAlgorithm_t.CRC16)     flow_id_calc;
    Hash<bit<(INDEX_WIDTH)>>(HashAlgorithm_t.CRC16)     rev_flow_id_calc;

    /* Calculate hash of the 5-tuple to represent the flow ID */
    action get_flow_ID() {
        meta.flow_ID = flow_id_calc.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr,hdr.tcp.src_port, hdr.tcp.dst_port, hdr.ipv4.protocol});
    }
    /* Calculate hash of the reversed 5-tuple to represent the reversed flow ID */
    action get_rev_flow_ID() {
        meta.rev_flow_ID = rev_flow_id_calc.get({hdr.ipv4.dst_addr, hdr.ipv4.src_addr, hdr.tcp.dst_port, hdr.tcp.src_port, hdr.ipv4.protocol});
    }

    /* Forward to a specific port upon classification */
    action ipv4_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    /* Custom Do Nothing Action */
    action nop(){}

    apply {
            
        /* Get flow ID using the 5-tuple */
        get_flow_ID();

        /* Check if the packet is a recirculated one (i.e., it holds the classification) */
        if(hdr.recirc.isValid()){
            ig_dprsr_md.digest_type = 1;
            meta.final_class = hdr.recirc.class_result;
            hdr.recirc.setInvalid();
            hdr.ethernet.ether_type = TYPE_IPV4;
            ipv4_forward(140);
        }
        /* Check if the packet is Client Hello */
        // else if(hdr.TLS_handshake.isValid() && hdr.TLS_handshake.type == 1){

        //     // ig_dprsr_md.mirror_type = 1;
        //     // meta.pkt_type = 1;
        //     // meta.ing_mir_ses = 28;

        //     /* Define the register index for the flow and its corresponding reversed flow */
        //     get_rev_flow_ID();
        //     set_flow_dir_reg.execute(meta.flow_ID);
        //     set_flow_dir_reg.execute(meta.rev_flow_ID);

        //     /* Set packet count by 1*/
        //     set_flow_pkt_count_reg.execute(meta.flow_ID);

        //     /* Store packet 0 length*/
        //     set_flow_pkt_length_0.execute(meta.flow_ID);

        
        // }

        // else if(hdr.TLS.isValid()){
        //     get_register_index();
        //     meta.pkt_count = get_update_flow_pkt_count_reg.execute(meta.register_index);

        //     if(meta.pkt_count < 9){
        //             // if(meta.pkt_count == 0){
        //             //     set_flow_pkt_length_0.execute(meta.register_index);
        //             // }
                    
        //             if(meta.pkt_count == 1){
        //                 set_flow_pkt_length_1.execute(meta.register_index);
        //             }
                    
        //             if(meta.pkt_count == 2){
        //                 set_flow_pkt_length_2.execute(meta.register_index);
        //             }
                    
        //             if(meta.pkt_count == 3){
        //                 set_flow_pkt_length_3.execute(meta.register_index);
        //             }
                    
        //             else{
        //                 set_flow_pkt_length_4.execute(meta.register_index);
        //             }
                
        //             if(meta.pkt_count == 5){
        //                 set_flow_pkt_length_5.execute(meta.register_index);
        //             }
                    
        //             if(meta.pkt_count == 6){
        //                 set_flow_pkt_length_6.execute(meta.register_index);
        //             }
                    
        //             if(meta.pkt_count == 7){
        //                 set_flow_pkt_length_7.execute(meta.register_index);
        //             }

        //             if(meta.pkt_count == 8){
        //                 set_flow_pkt_length_8.execute(meta.register_index);
        //             }
        //         }

        //     // check if # of packets required is met
        //     else if(meta.pkt_count == 9){

        //         // This header will hold the packet lengths to the egress pipeline
        //         hdr.packet_lengths.setValid();

        //         hdr.packet_lengths.pkt_len_0 = get_flow_pkt_length_0.execute(meta.register_index);
        //         hdr.packet_lengths.pkt_len_1 = get_flow_pkt_length_1.execute(meta.register_index);
        //         hdr.packet_lengths.pkt_len_2 = get_flow_pkt_length_2.execute(meta.register_index);
        //         hdr.packet_lengths.pkt_len_3 = get_flow_pkt_length_3.execute(meta.register_index);
        //         hdr.packet_lengths.pkt_len_4 = get_flow_pkt_length_4.execute(meta.register_index);
        //         hdr.packet_lengths.pkt_len_5 = get_flow_pkt_length_5.execute(meta.register_index);
        //         hdr.packet_lengths.pkt_len_6 = get_flow_pkt_length_6.execute(meta.register_index);
        //         hdr.packet_lengths.pkt_len_7 = get_flow_pkt_length_7.execute(meta.register_index);
        //         hdr.packet_lengths.pkt_len_8 = get_flow_pkt_length_8.execute(meta.register_index);
        //         hdr.packet_lengths.pkt_len_9 = hdr.TLS.len;

        //         recirculate(68);
        //     }                    
        // }
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
    Digest<flow_class_digest>() digest_flow_class;
    Mirror() mirror;

    apply {

        if (ig_dprsr_md.digest_type == 1) {
            // Pack digest and send to controller
            digest_flow_class.pack({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port, hdr.ipv4.protocol, meta.final_class,meta.pkt_count, meta.register_index});
        }
        

        /* we do not update checksum because we used ttl field for stats*/
        pkt.emit(hdr);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
struct my_egress_headers_t {

    Ethernet_h ethernet;
    recirc_h     recirc;
    packet_lengths_h packet_lengths;
	ipv4_h ipv4;

}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {

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

    bit<8> codeword0;
    bit<11> codeword1;
    bit<9> codeword2;
    bit<8> codeword3;
    bit<9> codeword4;
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
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_RECIRC: parse_recirc;
            default: accept;
        }
    }

    state parse_recirc{
        pkt.extract(hdr.recirc);
        transition parse_packet_lengths;
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
    action SetCode0(bit<3> code0, bit<4> code1, bit<2> code2, bit<3> code3, bit<2> code4) {
        meta.codeword0[7:5] = code0;
        meta.codeword1[10:7] = code1;
        meta.codeword2[8:7] = code2;
        meta.codeword3[7:5] = code3;
        meta.codeword4[8:7] = code4;
    }
    action SetCode1(bit<3> code0, bit<3> code1, bit<2> code2, bit<3> code3, bit<3> code4)  {
        meta.codeword0[4:2] = code0;
        meta.codeword1[6:4] = code1;
        meta.codeword2[6:5] = code2;
        meta.codeword3[4:2] = code3;
        meta.codeword4[6:4] = code4;
    }
    action SetCode2(bit<1> code0, bit<2> code2, bit<1> code3, bit<2> code4)  {
        meta.codeword0[1:1] = code0;
        // meta.codeword1[226:122] = code1;
        meta.codeword2[4:3] = code2;
        meta.codeword3[1:1] = code3;
        meta.codeword4[3:2] = code4;
    }
    action SetCode3( bit<2> code1, bit<1> code2, bit<1> code4)  { //gere
        // meta.codeword0[100:2]  = code0;
        meta.codeword1[3:2]  = code1;
        meta.codeword2[2:2]  = code2;
        // meta.codeword3[127:3]  = code3;
        meta.codeword4[1:1]  = code4;
    }
    action SetCode4(bit<1> code0, bit<2> code1, bit<2> code2, bit<1> code3, bit<1> code4) {
        meta.codeword0[0:0]  = code0;
        meta.codeword1[1:0]  = code1;
        meta.codeword2[1:0]  = code2;
        meta.codeword3[0:0]  = code3;
        meta.codeword4[0:0]  = code4;
    }
    // action SetCode5(bit<4> code0, bit<12> code1, bit<9> code2, bit<12> code3, bit<8> code4)  {
    //     meta.codeword0[75:72]  = code0;
    //     meta.codeword1[98:87]  = code1;
    //     meta.codeword2[79:71]  = code2;
    //     meta.codeword3[100:89]  = code3;
    //     meta.codeword4[87:80]  = code4;
    // }
    // action SetCode6(bit<7> code0, bit<6> code1, bit<6> code2, bit<13> code3, bit<9> code4)  {
    //     meta.codeword0[71:65]  = code0;
    //     meta.codeword1[86:81]  = code1;
    //     meta.codeword2[70:65]  = code2;
    //     meta.codeword3[88:76]  = code3;
    //     meta.codeword4[79:71]  = code4;
    // }
    // action SetCode7(bit<9> code0, bit<11> code1, bit<13> code2, bit<11> code3, bit<15> code4)  {
    //     meta.codeword0[64:56]  = code0;
    //     meta.codeword1[80:70]  = code1;
    //     meta.codeword2[64:52]  = code2;
    //     meta.codeword3[75:65]  = code3;
    //     meta.codeword4[70:56]  = code4;
    // }
    // action SetCode8(bit<17> code0, bit<20> code1, bit<14> code2, bit<21> code3, bit<18> code4)  {
    //     meta.codeword0[55:39]  = code0;
    //     meta.codeword1[69:50]  = code1;
    //     meta.codeword2[51:38]  = code2;
    //     meta.codeword3[64:44]  = code3;
    //     meta.codeword4[55:38]  = code4;
    // }
    // action SetCode9(bit<39> code0, bit<50> code1, bit<38> code2, bit<44> code3, bit<38> code4)  {
    //     meta.codeword0[38:0]  = code0;
    //     meta.codeword1[49:0]  = code1;
    //     meta.codeword2[37:0]  = code2;
    //     meta.codeword3[43:0]  = code3;
    //     meta.codeword4[37:0]  = code4;
    // }

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
	    size = 198;
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
    // table table_feature5{
	//     key = {hdr.packet_lengths.pkt_len_5: range @name("feature5");}
	//     actions = {@defaultonly nop; SetCode5;}
	//     size = 25;
    //     const default_action = nop();
	// }
    // table table_feature6{
	//     key = {hdr.packet_lengths.pkt_len_6: range @name("feature6");}
	//     actions = {@defaultonly nop; SetCode6;}
	//     size = 30;
    //     const default_action = nop();
	// }
    // table table_feature7{
	//     key = {hdr.packet_lengths.pkt_len_7: range @name("feature7");}
	//     actions = {@defaultonly nop; SetCode7;}
	//     size = 36;
    //     const default_action = nop();
	// }
    // table table_feature8{
	//     key = {hdr.packet_lengths.pkt_len_8: range @name("feature8");}
	//     actions = {@defaultonly nop; SetCode8;}
	//     size = 55;
    //     const default_action = nop();
	// }
    // table table_feature9{
	//     key = {hdr.packet_lengths.pkt_len_9: range @name("feature9");}
	//     actions = {@defaultonly nop; SetCode9;}
	//     size = 88;
    //     const default_action = nop();
	// }

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
	    size = 359;
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
        hdr.recirc.class_result = 0;
    }

    action set_final_class(bit<8> class_result) {
        hdr.recirc.class_result = class_result;
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
        // if(hdr.packet_lengths.isValid()){
        //     // apply feature tables to assign codes
        //         table_feature0.apply();
        //         table_feature1.apply();
        //         table_feature2.apply();
        //         table_feature3.apply();
        //         table_feature4.apply();
        //         table_feature5.apply();
        //         table_feature6.apply();
        //         table_feature7.apply();
        //         table_feature8.apply();
        //         table_feature9.apply();                        

        //     // apply code tables to assign labels
        //         code_table0.apply();
        //         code_table1.apply();
        //         code_table2.apply();
        //         code_table3.apply();
        //         code_table4.apply();

        //     // decide final class
        //     voting_table.apply();
        // }
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
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.recirc);
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