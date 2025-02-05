
/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

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
    action SetCode0(bit<3> code0, bit<5> code1, bit<3> code2, bit<4> code3, bit<5> code4) {
        meta.codeword0[9:7] = code0;
        meta.codeword1[10:6] = code1;
        meta.codeword2[11:9] = code2;
        meta.codeword3[7:4] = code3;
        meta.codeword4[12:8] = code4;
    }
    action SetCode1(bit<3> code0, bit<2> code1, bit<3> code2, bit<3> code3, bit<4> code4)  {
        meta.codeword0[6:4] = code0;
        meta.codeword1[5:4] = code1;
        meta.codeword2[8:6] = code2;
        meta.codeword3[3:1] = code3;
        meta.codeword4[7:4] = code4;
    }
    action SetCode2(bit<1> code0, bit<3> code2, bit<1> code3, bit<2> code4)  {
        meta.codeword0[3:3] = code0;
        // meta.codeword1[4:4] = code1;
        meta.codeword2[5:3] = code2;
        meta.codeword3[0:0] = code3;
        meta.codeword4[3:2] = code4;
    }
    action SetCode3( bit<2> code0, bit<2> code1, bit<1> code2, bit<1> code4)  { //gere
        meta.codeword0[2:1]  = code0;
        meta.codeword1[3:2]  = code1;
        meta.codeword2[2:2]  = code2;
        // meta.codeword3[127:3]  = code3;
        meta.codeword4[1:1]  = code4;
    }
    action SetCode4(bit<1> code0, bit<2> code1, bit<2> code2, bit<1> code4) {
        meta.codeword0[0:0]  = code0;
        meta.codeword1[1:0]  = code1;
        meta.codeword2[1:0]  = code2;
        // meta.codeword3[0:0]  = code3;
        meta.codeword4[0:0]  = code4;
    }

    /* Feature tables */
    table table_feature0{
	    key = {hdr.features.client_hello_len: range @name("feature0");}
	    actions = {@defaultonly nop; SetCode0;}
	    size = 20;
        const default_action = nop();
	}
    table table_feature1{
        key = {hdr.features.client_hello_exts_number: range @name("feature1");}
	    actions = {@defaultonly nop; SetCode1;}
	    size = 7;
        const default_action = nop();
	}
	table table_feature2{
        key = {hdr.features.server_hello_len: range @name("feature2");} 
	    actions = {@defaultonly nop; SetCode2;}
	    size = 7;
        const default_action = nop();
	}
    table table_feature3{
	    key = {hdr.features.server_hello_exts_number: range @name("feature3");}
	    actions = {@defaultonly nop; SetCode3;}
	    size = 4;
        const default_action = nop();
	}
    table table_feature4{
	    key = {hdr.features.tls_version: range @name("feature4");}
	    actions = {@defaultonly nop; SetCode4;}
	    size = 2;
        const default_action = nop();
	}

    /* Code tables */
	table code_table0{
	    key = {meta.codeword0: ternary;}
	    actions = {@defaultonly nop; SetClass0;}
	    size = 12;
        const default_action = nop();
	}
	table code_table1{
        key = {meta.codeword1: ternary;}
	    actions = {@defaultonly nop; SetClass1;}
	    size = 13;
        const default_action = nop();
	}
	table code_table2{
        key = {meta.codeword2: ternary;}
	    actions = {@defaultonly nop; SetClass2;}
	    size = 13;
        const default_action = nop();
	}
	table code_table3{
        key = {meta.codeword3: ternary;}
	    actions = {@defaultonly nop; SetClass3;}
	    size = 9;
        const default_action = nop();
	}
	table code_table4{
        key = {meta.codeword4: ternary;}
	    actions = {@defaultonly nop; SetClass4;}
	    size = 15;
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
        if(hdr.features.isValid()){
            if(hdr.features.client_hello_exts_number == 240){
                hdr.recirc.class_result = 3;
            }
            else{
                // apply feature tables to assign codes
                    table_feature0.apply();
                    table_feature1.apply();
                    table_feature2.apply();
                    table_feature3.apply();
                    table_feature4.apply();                       

                // apply code tables to assign labels
                    code_table0.apply();
                    code_table1.apply();
                    code_table2.apply();
                    code_table3.apply();
                    code_table4.apply();

                // decide final class
                voting_table.apply();
            }
        }
        if(hdr.mirror_md.isValid()){
            if(hdr.mirror_md.mirror_type == 11){
                hdr.ethernet.ether_type = 2000;
            }
            else if(hdr.mirror_md.mirror_type == 22){
                hdr.ethernet.ether_type = 2001;
            }
            hdr.mirror_md.setInvalid();
        }
    }
}