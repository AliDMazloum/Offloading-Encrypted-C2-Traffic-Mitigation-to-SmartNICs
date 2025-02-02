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

table_feature0.add_with_SetCode0(feature0_start=0, feature0_end=176, code0=0b000, code1=0b00000, code2=0b000, code3=0b0000, code4=0b00000)
table_feature0.add_with_SetCode0(feature0_start=177, feature0_end=177, code0=0b000, code1=0b10000, code2=0b000, code3=0b0000, code4=0b00000)
table_feature0.add_with_SetCode0(feature0_start=178, feature0_end=179, code0=0b000, code1=0b10000, code2=0b000, code3=0b0000, code4=0b10000)
table_feature0.add_with_SetCode0(feature0_start=180, feature0_end=180, code0=0b100, code1=0b10000, code2=0b000, code3=0b1000, code4=0b10000)
table_feature0.add_with_SetCode0(feature0_start=181, feature0_end=200, code0=0b100, code1=0b10000, code2=0b000, code3=0b1000, code4=0b11000)
table_feature0.add_with_SetCode0(feature0_start=201, feature0_end=203, code0=0b100, code1=0b10000, code2=0b100, code3=0b1000, code4=0b11000)
table_feature0.add_with_SetCode0(feature0_start=204, feature0_end=226, code0=0b100, code1=0b10000, code2=0b100, code3=0b1000, code4=0b11100)
table_feature0.add_with_SetCode0(feature0_start=227, feature0_end=236, code0=0b100, code1=0b10000, code2=0b100, code3=0b1100, code4=0b11100)
table_feature0.add_with_SetCode0(feature0_start=237, feature0_end=237, code0=0b100, code1=0b11000, code2=0b100, code3=0b1100, code4=0b11100)
table_feature0.add_with_SetCode0(feature0_start=238, feature0_end=249, code0=0b110, code1=0b11000, code2=0b100, code3=0b1100, code4=0b11100)
table_feature0.add_with_SetCode0(feature0_start=250, feature0_end=250, code0=0b110, code1=0b11100, code2=0b100, code3=0b1100, code4=0b11110)
table_feature0.add_with_SetCode0(feature0_start=251, feature0_end=350, code0=0b110, code1=0b11100, code2=0b100, code3=0b1110, code4=0b11110)
table_feature0.add_with_SetCode0(feature0_start=351, feature0_end=372, code0=0b110, code1=0b11110, code2=0b100, code3=0b1110, code4=0b11110)
table_feature0.add_with_SetCode0(feature0_start=373, feature0_end=380, code0=0b110, code1=0b11110, code2=0b110, code3=0b1110, code4=0b11110)
table_feature0.add_with_SetCode0(feature0_start=381, feature0_end=392, code0=0b111, code1=0b11110, code2=0b111, code3=0b1110, code4=0b11111)
table_feature0.add_with_SetCode0(feature0_start=393, feature0_end=466, code0=0b111, code1=0b11110, code2=0b111, code3=0b1111, code4=0b11111)
table_feature0.add_with_SetCode0(feature0_start=467, feature0_end=65535, code0=0b111, code1=0b11111, code2=0b111, code3=0b1111, code4=0b11111)

table_feature1.add_with_SetCode1(feature1_start=0, feature1_end=6, code0=0b000, code1=0b00, code2=0b000, code3=0b000, code4=0b0000)
table_feature1.add_with_SetCode1(feature1_start=7, feature1_end=7, code0=0b100, code1=0b10, code2=0b100, code3=0b100, code4=0b0000)
table_feature1.add_with_SetCode1(feature1_start=8, feature1_end=8, code0=0b100, code1=0b10, code2=0b100, code3=0b110, code4=0b0000)
table_feature1.add_with_SetCode1(feature1_start=9, feature1_end=9, code0=0b100, code1=0b10, code2=0b100, code3=0b110, code4=0b1000)
table_feature1.add_with_SetCode1(feature1_start=10, feature1_end=10, code0=0b100, code1=0b10, code2=0b100, code3=0b110, code4=0b1100)
table_feature1.add_with_SetCode1(feature1_start=11, feature1_end=11, code0=0b110, code1=0b10, code2=0b110, code3=0b110, code4=0b1110)
table_feature1.add_with_SetCode1(feature1_start=12, feature1_end=65535, code0=0b111, code1=0b11, code2=0b111, code3=0b111, code4=0b1111)

table_feature2.add_with_SetCode2(feature2_start=0, feature2_end=64, code0=0b0, code2=0b000, code3=0b0, code4=0b00)
table_feature2.add_with_SetCode2(feature2_start=65, feature2_end=65, code0=0b0, code2=0b100, code3=0b0, code4=0b00)
table_feature2.add_with_SetCode2(feature2_start=66, feature2_end=101, code0=0b0, code2=0b110, code3=0b0, code4=0b10)
table_feature2.add_with_SetCode2(feature2_start=102, feature2_end=111, code0=0b0, code2=0b110, code3=0b0, code4=0b11)
table_feature2.add_with_SetCode2(feature2_start=112, feature2_end=113, code0=0b0, code2=0b111, code3=0b0, code4=0b11)
table_feature2.add_with_SetCode2(feature2_start=114, feature2_end=116, code0=0b0, code2=0b111, code3=0b1, code4=0b11)
table_feature2.add_with_SetCode2(feature2_start=117, feature2_end=65535, code0=0b1, code2=0b111, code3=0b1, code4=0b11)

table_feature3.add_with_SetCode3(feature3_start=0, feature3_end=1, code0=0b00, code1=0b00, code2=0b0,  code4=0b0)
table_feature3.add_with_SetCode3(feature3_start=2, feature3_end=4, code0=0b00, code1=0b10, code2=0b0, code4=0b0)
table_feature3.add_with_SetCode3(feature3_start=5, feature3_end=5, code0=0b10, code1=0b11, code2=0b1, code4=0b1)
table_feature3.add_with_SetCode3(feature3_start=6, feature3_end=65535, code0=0b11, code1=0b11, code2=0b1, code4=0b1)

table_feature4.add_with_SetCode4(feature4_start=0, feature4_end=2, code0=0b0, code1=0b00, code2=0b00, code4=0b0)
table_feature4.add_with_SetCode4(feature4_start=3, feature4_end=65535, code0=0b1, code1=0b11, code2=0b11,  code4=0b1)

print("******************* ENTERED FEATURE TABLE RULES *****************")

code_table0.add_with_SetClass0(codeword0= 0b1000011000 , codeword0_mask= 0b1000011000 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b0000000000 , codeword0_mask= 0b1001000000 , classe= 2 )
code_table0.add_with_SetClass0(codeword0= 0b0001000000 , codeword0_mask= 0b1001000000 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b1000101000 , codeword0_mask= 0b1000111000 , classe= 2 )
code_table0.add_with_SetClass0(codeword0= 0b1000001000 , codeword0_mask= 0b1010111000 , classe= 2 )
code_table0.add_with_SetClass0(codeword0= 0b1010001000 , codeword0_mask= 0b1010111000 , classe= 2 )
code_table0.add_with_SetClass0(codeword0= 0b1100000000 , codeword0_mask= 0b1100001000 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b1000000000 , codeword0_mask= 0b1100001001 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b1000000001 , codeword0_mask= 0b1100001101 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b1000000101 , codeword0_mask= 0b1100001111 , classe= 2 )
code_table0.add_with_SetClass0(codeword0= 0b1000000111 , codeword0_mask= 0b1100001111 , classe= 1 )

code_table1.add_with_SetClass1(codeword1= 0b00000010000 , codeword1_mask= 0b00000010000 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b00000000000 , codeword1_mask= 0b00000010110 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b00000000010 , codeword1_mask= 0b00000011110 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b00000001010 , codeword1_mask= 0b10000011110 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b00000000100 , codeword1_mask= 0b01000010100 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b01000000100 , codeword1_mask= 0b01000010101 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b01000000101 , codeword1_mask= 0b01000010101 , classe= 2 )
code_table1.add_with_SetClass1(codeword1= 0b10000001010 , codeword1_mask= 0b10100111110 , classe= 2 )
code_table1.add_with_SetClass1(codeword1= 0b10000101010 , codeword1_mask= 0b10100111110 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b10100001010 , codeword1_mask= 0b10110011110 , classe= 2 )
code_table1.add_with_SetClass1(codeword1= 0b10110001010 , codeword1_mask= 0b10111011110 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b10111001010 , codeword1_mask= 0b10111011110 , classe= 2 )

code_table2.add_with_SetClass2(codeword2= 0b000001000000 , codeword2_mask= 0b000001000100 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b000000000000 , codeword2_mask= 0b000001001110 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b000000000010 , codeword2_mask= 0b000101001110 , classe= 2 )
code_table2.add_with_SetClass2(codeword2= 0b000100000010 , codeword2_mask= 0b000101001110 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b000000010100 , codeword2_mask= 0b000000010100 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b000000000100 , codeword2_mask= 0b000000010101 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b010000000101 , codeword2_mask= 0b010000010101 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b000000000101 , codeword2_mask= 0b010000110101 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b000000100101 , codeword2_mask= 0b110000110101 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b100000100101 , codeword2_mask= 0b110000110101 , classe= 2 )
code_table2.add_with_SetClass2(codeword2= 0b000010001000 , codeword2_mask= 0b000011001100 , classe= 2 )
code_table2.add_with_SetClass2(codeword2= 0b000000001000 , codeword2_mask= 0b001011001100 , classe= 2 )
code_table2.add_with_SetClass2(codeword2= 0b001000001000 , codeword2_mask= 0b001011001100 , classe= 2 )

code_table3.add_with_SetClass3(codeword3= 0b00000010 , codeword3_mask= 0b00000010 , classe= 1 )
code_table3.add_with_SetClass3(codeword3= 0b00000000 , codeword3_mask= 0b10101010 , classe= 2 )
code_table3.add_with_SetClass3(codeword3= 0b00001000 , codeword3_mask= 0b10101010 , classe= 1 )
code_table3.add_with_SetClass3(codeword3= 0b00100000 , codeword3_mask= 0b00100011 , classe= 1 )
code_table3.add_with_SetClass3(codeword3= 0b10000100 , codeword3_mask= 0b10100110 , classe= 1 )
code_table3.add_with_SetClass3(codeword3= 0b10000000 , codeword3_mask= 0b11100110 , classe= 1 )
code_table3.add_with_SetClass3(codeword3= 0b11000000 , codeword3_mask= 0b11100110 , classe= 2 )
code_table3.add_with_SetClass3(codeword3= 0b00100001 , codeword3_mask= 0b00110011 , classe= 2 )
code_table3.add_with_SetClass3(codeword3= 0b00110001 , codeword3_mask= 0b00110011 , classe= 2 )

code_table4.add_with_SetClass4(codeword4= 0b0000000010000 , codeword4_mask= 0b0000000010010 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b0000000000000 , codeword4_mask= 0b0000000010011 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b0000000000001 , codeword4_mask= 0b1000000010011 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b0000000001010 , codeword4_mask= 0b0000000001010 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b0000010000010 , codeword4_mask= 0b0000010001010 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b0000000000010 , codeword4_mask= 0b0010010001010 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b0010000000010 , codeword4_mask= 0b0010010001010 , classe= 2 )
code_table4.add_with_SetClass4(codeword4= 0b1000000000001 , codeword4_mask= 0b1100001010011 , classe= 2 )
code_table4.add_with_SetClass4(codeword4= 0b1100000000001 , codeword4_mask= 0b1100001010011 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b1000001000001 , codeword4_mask= 0b1001001010011 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b1001001000001 , codeword4_mask= 0b1001001010111 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b1001001100101 , codeword4_mask= 0b1001001110111 , classe= 2 )
code_table4.add_with_SetClass4(codeword4= 0b1001001000101 , codeword4_mask= 0b1001101110111 , classe= 2 )
code_table4.add_with_SetClass4(codeword4= 0b1001101000101 , codeword4_mask= 0b1001101110111 , classe= 2 )

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
