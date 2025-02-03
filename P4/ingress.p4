/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control calc_long_hash (in bit<248> servername, out bit<16> hash) (bit<16> coeff) {
    CRCPolynomial<bit<16>>(coeff = coeff, reversed = false, msb = false, extended = false, init=0xFFFF, xor=0xFFFF) poly;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly) hash_algo;
    action do_hash(){
        hash = hash_algo.get({servername});
    }
    apply {
        do_hash();
    }
}
control calc_long_hash32 (in bit<248> servername, out bit<32> hash) (bit<32> coeff) {
    CRCPolynomial<bit<32>>(coeff = coeff, reversed = true, msb = false, extended = false, init=0xFFFFFFFF, xor=0xFFFFFFFF) poly;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly) hash_algo;
    action do_hash(){
        hash = hash_algo.get({servername});
    }
    apply {
        do_hash();
    }
}

control calc_long_hash32_2 (in bit<256> servername_2, out bit<32> hash) (bit<32> coeff) {
    CRCPolynomial<bit<32>>(coeff = coeff, reversed = true, msb = false, extended = false, init=0xFFFFFFFF, xor=0xFFFFFFFF) poly;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly) hash_algo;
    action do_hash(){
        hash = hash_algo.get({servername_2});
    }
    apply {
        do_hash();
    }
}

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

    calc_long_hash(coeff=0x1021) servername_hash_fc;
    calc_long_hash32(coeff=0x1EDC6F41) servername_hash_fc32;
    calc_long_hash32_2(coeff=0x1EDC6F41) servername_hash_fc32_2;
    bit<248> servername;
    bit<32> servername_hash32;
    bit<256> servername_2;
    bit<32> servername_hash32_2;

    bit<32> hash_value;

    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) domain_stats;

    action send_using_port(PortId_t port){
	    ig_tm_md.ucast_egress_port = port;   
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action send_with_count(PortId_t port){
	    ig_tm_md.ucast_egress_port = port;   
        domain_stats.count();
    }

    action drop_with_count() {
        ig_dprsr_md.drop_ctl = 1;
        domain_stats.count();
    }


    table forwarding {
        key = { 
		    // ig_intr_md.ingress_port : exact; 
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            send_using_port; 
            drop;
        }
    }

    table fine_grained {
        key = {
            hash_value: exact;
        }
        actions = {
            send_using_port;
            NoAction;
        }
        size = 10000;
        default_action = NoAction();
    }

    
    table coarse_grained {
        key = {
            hdr.servername_part1.part: ternary;
            hdr.servername_part2.part: ternary;
            hdr.servername_part4.part: ternary;
            hdr.servername_part8.part: ternary;
            hdr.servername_part16.part: ternary;
        }
        actions = {
            @defaultonly NoAction;
            send_with_count;
            drop_with_count;
        }
        size = 1500;
        counters = domain_stats;
    }

    /*---------------------------------------Start  Register Defenisions ------------------------------------*/
    /* Register for Client extentions number per flow */
    Register<bit<8>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) flow_client_exts_num;
    /* Register set action */
    RegisterAction<bit<8>,bit<(INDEX_WIDTH)>,bit<16>>(flow_client_exts_num)
    set_flow_client_exts_num = {
        void apply(inout bit<8> exts_num) {
            exts_num = hdr.client_hello_dpdk.exts_num[7:0];
        }
    };
    /* Register read action */
    RegisterAction<bit<16>,bit<(INDEX_WIDTH)>,bit<16>>(flow_client_exts_num)
    get_flow_client_exts_num = {
        void apply(inout bit<16> exts_num, out bit<16> output) {
            output = exts_num;
            exts_num = 0;
        }
    };

    /* Register for Client Hello len per flow */
    Register<bit<INDEX_WIDTH>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) flow_client_hello_len;
    /* Register set action */
    RegisterAction<bit<INDEX_WIDTH>,bit<(INDEX_WIDTH)>,bit<INDEX_WIDTH>>(flow_client_hello_len)
    set_flow_client_hello_len = {
        void apply(inout bit<INDEX_WIDTH> len) {
            len = hdr.client_hello_dpdk.len;
        }
    };
    /* Register read action */
    RegisterAction<bit<INDEX_WIDTH>,bit<(INDEX_WIDTH)>,bit<INDEX_WIDTH>>(flow_client_hello_len)
    get_flow_client_hello_len = {
        void apply(inout bit<INDEX_WIDTH> len, out bit<INDEX_WIDTH> output) {
            output = len;
            len = 0;
        }
    };

    // /* Register for Server Hello First Observation Timestamp */
    // Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) server_hello_first_obs;
    // /* Register set action */
    // RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(server_hello_first_obs)
    // set_server_hello_first_obsm = {
    //     void apply(inout bit<32> timestamp) {
    //         exts_num = hdr.client_hello_dpdk.exts_num[7:0];
    //     }
    // };
    // /* Register read action */
    // RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(server_hello_first_obs)
    // get_server_hello_first_obs = {
    //     void apply(inout bit<32> exts_num, out bit<32> output) {
    //         output = exts_num;
    //         exts_num = 0;
    //     }
    // };

    #define TIMESTAMP ig_intr_md.ingress_mac_tstamp[31:0]
    /* Register for Server Hello First Observation Timestamp */
    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) server_hello_first_obs;
    /* Register initial observation timestamp*/
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(server_hello_first_obs)
    set_server_hello_first_obs = {
        void apply(inout bit<32> timestamp) {
            timestamp = TIMESTAMP;
        }
    };
    /* Calculate DPDK processing time */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(server_hello_first_obs)
    set_DPDK_proc_time = {
        void apply(inout bit<32> timestamp) {
            if(timestamp < TIMESTAMP){
                timestamp = TIMESTAMP - timestamp;
            }
            else{
                timestamp = 0;
            }
        }
    };
    /* Get DPDK processing time */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(server_hello_first_obs)
    get_DPDK_proc_time = {
        void apply(inout bit<32> timestamp, out bit<32> output) {
            output = timestamp;
        }
    };

    /* Register for Server Hello Second Observation Timestamp */
    Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) server_hello_second_obs;
    /* Register Second observation timestamp*/
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(server_hello_second_obs)
    set_server_hello_second_obs = {
        void apply(inout bit<32> timestamp) {
            timestamp = TIMESTAMP;
        }
    };
    /* Calculate forwarding action processing time */
    RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(server_hello_second_obs)
    calc_frwd_proc_time = {
        void apply(inout bit<32> timestamp, out bit<32> output) {
            if(timestamp < TIMESTAMP){
                output = TIMESTAMP - timestamp;
            }
            else{
                output = 0;
            }
            timestamp = 0;
        }
    };

    

    // /* Register for Server Hello Second Observation Timestamp */
    // Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) server_hello_second_obs;
    // /* Register set action */
    // RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(server_hello_second_obs)
    // set_server_hello_second_obs = {
    //     void apply(inout bit<32> timestamp) {
    //         timestamp = TIMESTAMP;
    //     }
    // };
    // /* Register read action */
    // RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(server_hello_second_obs)
    // get_server_hello_second_obs = {
    //     void apply(inout bit<32> timestamp, out bit<32> output) {
    //         output = timestamp;
    //         timestamp = 0;
    //     }
    // };

    // /* Register for Server Hello third Observation Timestamp */
    // Register<bit<32>,bit<(INDEX_WIDTH)>>(MAX_REGISTER_ENTRIES) server_hello_third_obs;
    // /* Register set action */
    // RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(server_hello_third_obs)
    // set_server_hello_third_obs = {
    //     void apply(inout bit<32> timestamp) {
    //         timestamp = TIMESTAMP;
    //     }
    // };
    // /* Register read action */
    // RegisterAction<bit<32>,bit<(INDEX_WIDTH)>,bit<32>>(server_hello_third_obs)
    // get_server_hello_third_obs = {
    //     void apply(inout bit<32> timestamp, out bit<32> output) {
    //         output = TIMESTAMP - timestamp;
    //         timestamp = 0;
    //     }
    // };

    /*---------------------------------------End Register Defenisions ------------------------------------*/



    /*---------------------------------------start Hash Defenisions ------------------------------------*/

    /* Declaration of the hashes*/
    Hash<bit<(INDEX_WIDTH)>>(HashAlgorithm_t.CRC16)     flow_id_calc;
    Hash<bit<(INDEX_WIDTH)>>(HashAlgorithm_t.CRC16)     rev_flow_id_calc;

    /* Calculate hash of the 5-tuple to represent the flow ID */
    action get_flow_ID() {
        meta.flow_ID = flow_id_calc.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr,hdr.tcp_ports.src_port, hdr.tcp_ports.dst_port, hdr.ipv4.protocol});
    }
    /* Calculate hash of the reversed 5-tuple to represent the reversed flow ID */
    action get_rev_flow_ID() {
        meta.rev_flow_ID = rev_flow_id_calc.get({hdr.ipv4.dst_addr, hdr.ipv4.src_addr, hdr.tcp_ports.dst_port, hdr.tcp_ports.src_port, hdr.ipv4.protocol});
    }

    action recirculate(bit<7> recirc_port) {
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
        ig_tm_md.ucast_egress_port[6:0] = recirc_port;
        hdr.recirc.setValid();
        hdr.ethernet.ether_type = TYPE_RECIRC;
    }

    /*---------------------------------------End Hash Defenisions ------------------------------------*/

    apply {
        if(hdr.dpdk.isValid()){ //Coming from the NIC
            if(hdr.client_hello_dpdk.isValid()){
                get_flow_ID();
                meta.flow_ID =  meta.flow_ID >> 1;
                set_flow_client_exts_num.execute(meta.flow_ID);
                set_flow_client_hello_len.execute(meta.flow_ID);
                // ig_dprsr_md.digest_type = 2;
                // drop();
            }
            else if(hdr.server_hello_dpdk.isValid()){
                get_rev_flow_ID();
                meta.rev_flow_ID = meta.rev_flow_ID >>1;
                set_DPDK_proc_time.execute(meta.rev_flow_ID);
                set_server_hello_second_obs.execute(meta.rev_flow_ID);
                hdr.client_hello_dpdk.setValid();
                hdr.client_hello_dpdk.exts_num =  (bit<16>)get_flow_client_exts_num.execute(meta.rev_flow_ID);
                hdr.client_hello_dpdk.len = get_flow_client_hello_len.execute(meta.rev_flow_ID);
                hdr.dpdk.setInvalid();
                recirculate(68);
                // drop();
            }
        }
        else if (hdr.client_servername.isValid() && hdr.client_servername.sni_len > 0) {

            ig_dprsr_md.mirror_type = 1;
            meta.pkt_type = 11;
            meta.ing_mir_ses = 28;
            // ig_tm_md.ucast_egress_port = 156;

            servername[7:0] = hdr.servername_part1.part;
            servername[23:8] = hdr.servername_part2.part;
            servername[55:24] = hdr.servername_part4.part;
            servername[119:56] = hdr.servername_part8.part;
            servername[247:120] = hdr.servername_part16.part;
            // servername_2 = hdr.servername_part32.part;

            servername_hash_fc32.apply(servername, servername_hash32);
            // servername_hash_fc32_2.apply(servername_2, servername_hash32_2);

            hash_value[31:10] = servername_hash32[31:10];
            // hash_value[9:0] = servername_hash32_2[9:0];

            // fine-grained
            fine_grained.apply();
            
            // coarse-grained // service monitoring
            coarse_grained.apply();

        }
        else if(hdr.tls_client_hello.isValid() || meta.unparsed == 1){
            ig_dprsr_md.mirror_type = 1;
            meta.pkt_type = 11;
            meta.ing_mir_ses = 28;
            // drop();
        }
        else if(hdr.tls_server_hello.isValid()){
            get_rev_flow_ID();
            meta.rev_flow_ID = meta.rev_flow_ID >>1;
            set_server_hello_first_obs.execute(meta.rev_flow_ID);
            ig_dprsr_md.mirror_type = 1;
            meta.pkt_type = 22;
            meta.ing_mir_ses = 28;
            // hdr.server_hello_dpdk.setValid();
        }
        else if(hdr.recirc.isValid()){
            get_flow_ID();
            get_rev_flow_ID();
            meta.flow_ID =  meta.flow_ID >> 1;
            meta.rev_flow_ID = meta.rev_flow_ID >>1;
            meta.frwd_proc_time = calc_frwd_proc_time.execute(meta.rev_flow_ID);
            meta.DPDK_proc_time = get_DPDK_proc_time.execute(meta.rev_flow_ID);
            ig_dprsr_md.digest_type = 3;
            hdr.ethernet.ether_type = ETHERTYPE_IPV4;
            meta.final_class = hdr.recirc.class_result;
            // ig_dprsr_md.digest_type = 1; //Digest to report classification result
            if(hdr.recirc.class_result == 1){
                hdr.recirc.setInvalid();
                hdr.features.setInvalid();
                ig_tm_md.ucast_egress_port = 140;
            }
            else{
                drop();
            }
            // ig_tm_md.ucast_egress_port = 140;
        }
    }
}