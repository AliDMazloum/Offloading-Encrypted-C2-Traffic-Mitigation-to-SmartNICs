    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{

    Digest<processing_time_digest>() digest_proc_time;

    apply {

        if(ig_dprsr_md.digest_type == 1) {
            digest_proc_time.pack({meta.flow_ID, meta.proc_time});
        }

        pkt.emit(hdr);
    }
}
