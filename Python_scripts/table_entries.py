from netaddr import IPAddress

p4 = bfrt.noms_20_5_4.pipe


# This script configures QSFP ports automatically on the TOFINO Switch
# Adapted from ICA-1131 Intel Connectivity Academy Course
for qsfp_cage in [1, 5]:
    for lane in range(0, 1):
        dp = bfrt.port.port_hdl_info.get(CONN_ID = qsfp_cage, CHNL_ID = lane, print_ents = False).data[b'$DEV_PORT']
        bfrt.port.port.add(DEV_PORT= dp, SPEED = "BF_SPEED_100G", FEC = "BF_FEC_TYP_NONE", AUTO_NEGOTIATION = "PM_AN_FORCE_DISABLE", PORT_ENABLE = True)


def clear_all(verbose=True, batching=True):
    global p4
    global bfrt
    for table_types in (['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR'],
                        ['SELECTOR'],
                        ['ACTION_PROFILE']):
        for table in p4.info(return_info=True, print_info=False):
            if table['type'] in table_types:
                if verbose:
                    print("Clearing table {:<40} ... ".
                          format(table['full_name']), end='', flush=True)
                table['node'].clear(batch=batching)
                if verbose:
                    print('Done')

clear_all(verbose=True)

voting_table = p4.Ingress.voting_table
target_flows_table = p4.Ingress.target_flows_table
table_feature0 = p4.Ingress.table_feature0
table_feature1 = p4.Ingress.table_feature1
table_feature2 = p4.Ingress.table_feature2
table_feature3 = p4.Ingress.table_feature3
table_feature4 = p4.Ingress.table_feature4

code_table0 = p4.Ingress.code_table0
code_table1 = p4.Ingress.code_table1
code_table2 = p4.Ingress.code_table2
code_table3 = p4.Ingress.code_table3
code_table4 = p4.Ingress.code_table4

table_feature0.add_with_SetCode0(feature0_start=0, feature0_end=182, code0=0b000, code1=0b0000, code2=0b00, code3=0b000, code4=0b00)
table_feature0.add_with_SetCode0(feature0_start=183, feature0_end=183, code0=0b000, code1=0b1000, code2=0b00, code3=0b000, code4=0b00)
table_feature0.add_with_SetCode0(feature0_start=184, feature0_end=240, code0=0b100, code1=0b1100, code2=0b00, code3=0b100, code4=0b00)
table_feature0.add_with_SetCode0(feature0_start=241, feature0_end=254, code0=0b100, code1=0b1110, code2=0b00, code3=0b100, code4=0b10)
table_feature0.add_with_SetCode0(feature0_start=255, feature0_end=376, code0=0b100, code1=0b1110, code2=0b00, code3=0b110, code4=0b10)
table_feature0.add_with_SetCode0(feature0_start=377, feature0_end=384, code0=0b100, code1=0b1110, code2=0b10, code3=0b110, code4=0b10)
table_feature0.add_with_SetCode0(feature0_start=385, feature0_end=512, code0=0b110, code1=0b1111, code2=0b11, code3=0b111, code4=0b11)
table_feature0.add_with_SetCode0(feature0_start=513, feature0_end=65535, code0=0b111, code1=0b1111, code2=0b11, code3=0b111, code4=0b11)

table_feature1.add_with_SetCode1(feature1_start=0, feature1_end=7, code0=0b000, code1=0b000, code2=0b00, code3=0b000, code4=0b000)
table_feature1.add_with_SetCode1(feature1_start=8, feature1_end=8, code0=0b100, code1=0b000, code2=0b10, code3=0b100, code4=0b100)
table_feature1.add_with_SetCode1(feature1_start=9, feature1_end=9, code0=0b110, code1=0b100, code2=0b10, code3=0b110, code4=0b100)
table_feature1.add_with_SetCode1(feature1_start=10, feature1_end=10, code0=0b110, code1=0b110, code2=0b10, code3=0b110, code4=0b100)
table_feature1.add_with_SetCode1(feature1_start=11, feature1_end=11, code0=0b111, code1=0b111, code2=0b11, code3=0b111, code4=0b110)
table_feature1.add_with_SetCode1(feature1_start=12, feature1_end=65535, code0=0b111, code1=0b111, code2=0b11, code3=0b111, code4=0b111)

table_feature2.add_with_SetCode2(feature2_start=0, feature2_end=66, code0=0b0, code1=0b, code2=0b00, code3=0b0, code4=0b00)
table_feature2.add_with_SetCode2(feature2_start=67, feature2_end=69, code0=0b0, code1=0b, code2=0b00, code3=0b1, code4=0b00)
table_feature2.add_with_SetCode2(feature2_start=70, feature2_end=927, code0=0b0, code1=0b, code2=0b10, code3=0b1, code4=0b10)
table_feature2.add_with_SetCode2(feature2_start=928, feature2_end=1917, code0=0b0, code1=0b, code2=0b11, code3=0b1, code4=0b11)
table_feature2.add_with_SetCode2(feature2_start=1918, feature2_end=65535, code0=0b1, code1=0b, code2=0b11, code3=0b1, code4=0b11)

table_feature3.add_with_SetCode3(feature3_start=0, feature3_end=3, code0=0b, code1=0b00, code2=0b0, code3=0b, code4=0b0)
table_feature3.add_with_SetCode3(feature3_start=4, feature3_end=4, code0=0b, code1=0b10, code2=0b0, code3=0b, code4=0b0)
table_feature3.add_with_SetCode3(feature3_start=5, feature3_end=65535, code0=0b, code1=0b11, code2=0b1, code3=0b, code4=0b1)

table_feature4.add_with_SetCode4(feature4_start=0, feature4_end=2, code0=0b0, code1=0b00, code2=0b00, code3=0b0, code4=0b0)
table_feature4.add_with_SetCode4(feature4_start=3, feature4_end=65535, code0=0b1, code1=0b11, code2=0b11, code3=0b1, code4=0b1)

print("******************* ENTERED FEATURE TABLE RULES *****************")

code_table0.add_with_SetClass0(codeword0= 0b00100000 , codeword0_mask= 0b00100000 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b00000100 , codeword0_mask= 0b00100100 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b10000000 , codeword0_mask= 0b10100101 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b00000000 , codeword0_mask= 0b10110101 , classe= 2 )
code_table0.add_with_SetClass0(codeword0= 0b00010000 , codeword0_mask= 0b10110101 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b00000011 , codeword0_mask= 0b00100111 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b00000001 , codeword0_mask= 0b00101111 , classe= 2 )
code_table0.add_with_SetClass0(codeword0= 0b00001001 , codeword0_mask= 0b01101111 , classe= 2 )
code_table0.add_with_SetClass0(codeword0= 0b01001001 , codeword0_mask= 0b01101111 , classe= 2 )

code_table1.add_with_SetClass1(codeword1= 0b00000010000 , codeword1_mask= 0b00000010000 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b00000000000 , codeword1_mask= 0b00000011110 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b01000001000 , codeword1_mask= 0b01000011110 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b00010000010 , codeword1_mask= 0b00010010110 , classe= 2 )
code_table1.add_with_SetClass1(codeword1= 0b00000000010 , codeword1_mask= 0b00010110110 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b00000100010 , codeword1_mask= 0b00010110110 , classe= 2 )
code_table1.add_with_SetClass1(codeword1= 0b00000001000 , codeword1_mask= 0b11000011110 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b10000001000 , codeword1_mask= 0b11001011110 , classe= 2 )
code_table1.add_with_SetClass1(codeword1= 0b10001001000 , codeword1_mask= 0b11001011110 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b00000000100 , codeword1_mask= 0b00100010100 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b00100000100 , codeword1_mask= 0b00100010101 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b00100000101 , codeword1_mask= 0b00100010101 , classe= 2 )

code_table2.add_with_SetClass2(codeword2= 0b000100000 , codeword2_mask= 0b000100100 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b000001000 , codeword2_mask= 0b000101100 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b000000000 , codeword2_mask= 0b001101110 , classe= 2 )
code_table2.add_with_SetClass2(codeword2= 0b001000000 , codeword2_mask= 0b001101110 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b000000010 , codeword2_mask= 0b010101110 , classe= 2 )
code_table2.add_with_SetClass2(codeword2= 0b010000010 , codeword2_mask= 0b010101110 , classe= 2 )
code_table2.add_with_SetClass2(codeword2= 0b000010100 , codeword2_mask= 0b000010100 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b000000100 , codeword2_mask= 0b000010101 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b000000101 , codeword2_mask= 0b100010101 , classe= 2 )
code_table2.add_with_SetClass2(codeword2= 0b100000101 , codeword2_mask= 0b100010101 , classe= 1 )

code_table3.add_with_SetClass3(codeword3= 0b00000100 , codeword3_mask= 0b00000100 , classe= 1 )
code_table3.add_with_SetClass3(codeword3= 0b00000010 , codeword3_mask= 0b11000110 , classe= 1 )
code_table3.add_with_SetClass3(codeword3= 0b01000000 , codeword3_mask= 0b01100100 , classe= 2 )
code_table3.add_with_SetClass3(codeword3= 0b01100000 , codeword3_mask= 0b01100100 , classe= 2 )
code_table3.add_with_SetClass3(codeword3= 0b00000000 , codeword3_mask= 0b11001110 , classe= 2 )
code_table3.add_with_SetClass3(codeword3= 0b00001000 , codeword3_mask= 0b11001110 , classe= 1 )
code_table3.add_with_SetClass3(codeword3= 0b10000000 , codeword3_mask= 0b11000101 , classe= 1 )
code_table3.add_with_SetClass3(codeword3= 0b10000001 , codeword3_mask= 0b11010101 , classe= 2 )
code_table3.add_with_SetClass3(codeword3= 0b10010001 , codeword3_mask= 0b11010101 , classe= 1 )

code_table4.add_with_SetClass4(codeword4= 0b000100000 , codeword4_mask= 0b000100010 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b000000100 , codeword4_mask= 0b000100110 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b000000000 , codeword4_mask= 0b101100110 , classe= 2 )
code_table4.add_with_SetClass4(codeword4= 0b001000000 , codeword4_mask= 0b101100110 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b100000000 , codeword4_mask= 0b110100110 , classe= 2 )
code_table4.add_with_SetClass4(codeword4= 0b110000000 , codeword4_mask= 0b110100110 , classe= 2 )
code_table4.add_with_SetClass4(codeword4= 0b000001010 , codeword4_mask= 0b000001010 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b000000010 , codeword4_mask= 0b000001011 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b000000011 , codeword4_mask= 0b000011011 , classe= 2 )
code_table4.add_with_SetClass4(codeword4= 0b000010011 , codeword4_mask= 0b000011011 , classe= 1 )

voting_table.add_with_set_final_class(class0=1, class1=1, class2=1, class3=1, class4=1, class_result=1)
voting_table.add_with_set_final_class(class0=1, class1=1, class2=1, class3=1, class4=2, class_result=1)
voting_table.add_with_set_final_class(class0=1, class1=1, class2=1, class3=2, class4=1, class_result=1)
voting_table.add_with_set_final_class(class0=1, class1=1, class2=1, class3=2, class4=2, class_result=1)
voting_table.add_with_set_final_class(class0=1, class1=1, class2=2, class3=1, class4=1, class_result=1)
voting_table.add_with_set_final_class(class0=1, class1=1, class2=2, class3=1, class4=2, class_result=1)
voting_table.add_with_set_final_class(class0=1, class1=1, class2=2, class3=2, class4=1, class_result=1)
voting_table.add_with_set_final_class(class0=1, class1=1, class2=2, class3=2, class4=2, class_result=2)
voting_table.add_with_set_final_class(class0=1, class1=2, class2=1, class3=1, class4=1, class_result=1)
voting_table.add_with_set_final_class(class0=1, class1=2, class2=1, class3=1, class4=2, class_result=1)
voting_table.add_with_set_final_class(class0=1, class1=2, class2=1, class3=2, class4=1, class_result=1)
voting_table.add_with_set_final_class(class0=1, class1=2, class2=1, class3=2, class4=2, class_result=2)
voting_table.add_with_set_final_class(class0=1, class1=2, class2=2, class3=1, class4=1, class_result=1)
voting_table.add_with_set_final_class(class0=1, class1=2, class2=2, class3=1, class4=2, class_result=2)
voting_table.add_with_set_final_class(class0=1, class1=2, class2=2, class3=2, class4=1, class_result=2)
voting_table.add_with_set_final_class(class0=1, class1=2, class2=2, class3=2, class4=2, class_result=2)
voting_table.add_with_set_final_class(class0=2, class1=1, class2=1, class3=1, class4=1, class_result=1)
voting_table.add_with_set_final_class(class0=2, class1=1, class2=1, class3=1, class4=2, class_result=1)
voting_table.add_with_set_final_class(class0=2, class1=1, class2=1, class3=2, class4=1, class_result=1)
voting_table.add_with_set_final_class(class0=2, class1=1, class2=1, class3=2, class4=2, class_result=2)
voting_table.add_with_set_final_class(class0=2, class1=1, class2=2, class3=1, class4=1, class_result=1)
voting_table.add_with_set_final_class(class0=2, class1=1, class2=2, class3=1, class4=2, class_result=2)
voting_table.add_with_set_final_class(class0=2, class1=1, class2=2, class3=2, class4=1, class_result=2)
voting_table.add_with_set_final_class(class0=2, class1=1, class2=2, class3=2, class4=2, class_result=2)
voting_table.add_with_set_final_class(class0=2, class1=2, class2=1, class3=1, class4=1, class_result=1)
voting_table.add_with_set_final_class(class0=2, class1=2, class2=1, class3=1, class4=2, class_result=2)
voting_table.add_with_set_final_class(class0=2, class1=2, class2=1, class3=2, class4=1, class_result=2)
voting_table.add_with_set_final_class(class0=2, class1=2, class2=1, class3=2, class4=2, class_result=2)
voting_table.add_with_set_final_class(class0=2, class1=2, class2=2, class3=1, class4=1, class_result=2)
voting_table.add_with_set_final_class(class0=2, class1=2, class2=2, class3=1, class4=2, class_result=2)
voting_table.add_with_set_final_class(class0=2, class1=2, class2=2, class3=2, class4=1, class_result=2)
voting_table.add_with_set_final_class(class0=2, class1=2, class2=2, class3=2, class4=2, class_result=2)
 
bfrt.complete_operations()
