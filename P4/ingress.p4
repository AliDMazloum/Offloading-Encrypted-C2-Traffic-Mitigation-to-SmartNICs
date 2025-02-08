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


    apply {
        if(ig_intr_md.ingress_port == 132){
            ig_tm_md.ucast_egress_port = 148;
        }
        else if(ig_intr_md.ingress_port == 148){
            ig_tm_md.ucast_egress_port = 132;
        }
    }
}