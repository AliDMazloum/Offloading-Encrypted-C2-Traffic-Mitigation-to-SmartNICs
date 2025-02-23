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

    #define TIMESTAMP ig_intr_md.ingress_mac_tstamp[31:0]
    /* Register for Server Hello First Observation Timestamp */
    Register<bit<32>,bit<(16)>>(65536) timer_reg;
    /* Register initial observation timestamp*/
    RegisterAction<bit<32>,bit<(16)>,bit<32>>(timer_reg)
    set_timer = {
        void apply(inout bit<32> timestamp) {
            timestamp = TIMESTAMP;
        }
    };
    /* Calculate DPDK processing time */
    RegisterAction<bit<32>,bit<(16)>,bit<32>>(timer_reg)
    get_timer = {
        void apply(inout bit<32> timestamp,out bit<32> output) {
            if(timestamp < TIMESTAMP && timestamp > 0){
                output = TIMESTAMP - timestamp;
            }
            else{
                output = 0;
            }
            timestamp = 0;
        }
    };

    /*---------------------------------------start Hash Defenisions ------------------------------------*/

    /* Declaration of the hashes*/
    Hash<bit<(16)>>(HashAlgorithm_t.CRC16)     flow_id_calc;

    /* Calculate hash of the 5-tuple to represent the flow ID */
    action get_flow_ID() {
        meta.flow_ID = flow_id_calc.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr,hdr.tcp.src_port, hdr.tcp.dst_port, hdr.ipv4.protocol});
    }


    apply {

        get_flow_ID();
        if(ig_intr_md.ingress_port == 132){
            if(hdr.tcp.isValid()) {
                set_timer.execute(meta.flow_ID);
            }
            ig_tm_md.ucast_egress_port = 156;
        }
        else if(ig_intr_md.ingress_port == 140){
            // if(hdr.tcp.isValid()) {
            //     set_timer.execute(meta.flow_ID);
            // }
            ig_tm_md.ucast_egress_port = 148;
        }
        else if(ig_intr_md.ingress_port == 148){
            // if(hdr.tcp.isValid()) {
            //     meta.proc_time = get_timer.execute(meta.flow_ID);
            // }
            ig_tm_md.ucast_egress_port = 140;
        }
        else if(ig_intr_md.ingress_port == 156){
            if(hdr.tcp.isValid()) {
                meta.proc_time = get_timer.execute(meta.flow_ID);
            }
            ig_dprsr_md.digest_type = 1;
            ig_tm_md.ucast_egress_port = 132;
        }
    }
}