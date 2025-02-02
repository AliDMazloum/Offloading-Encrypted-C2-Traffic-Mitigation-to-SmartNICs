    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{

    Digest<flow_class_digest>() digest_flow_class;
    Digest<client_hello_digest>() digest_client_hello;
    Digest<processing_time_digest>() digest_proc_time;
    Mirror() mirror;

    apply {

        if (ig_dprsr_md.digest_type == 1) {
            // Pack digest and send to controller
            digest_flow_class.pack({meta.flow_ID, meta.rev_flow_ID, hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp_ports.src_port,
            hdr.tcp_ports.dst_port, hdr.features.client_hello_len, hdr.features.client_hello_exts_number, 
            hdr.features.server_hello_len, hdr.features.server_hello_exts_number, hdr.features.tls_version, meta.final_class});
        }
        else if(ig_dprsr_md.digest_type == 2) {
            digest_client_hello.pack({meta.flow_ID, hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp_ports.src_port,
            hdr.tcp_ports.dst_port, hdr.client_hello_dpdk.len, hdr.client_hello_dpdk.exts_num});
        }else if(ig_dprsr_md.digest_type == 3) {
            digest_proc_time.pack({meta.flow_ID, meta.DPDK_proc_time, meta.frwd_proc_time});
        }
        if (ig_dprsr_md.mirror_type == 1) {
            mirror.emit<mirror_h>(meta.ing_mir_ses, {meta.pkt_type});
        }

        pkt.emit(hdr);
    }
}
