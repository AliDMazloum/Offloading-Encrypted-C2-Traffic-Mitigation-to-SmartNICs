from netaddr import IPAddress
import subprocess
import time

p4 = bfrt.basic.pipe

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

voting_table = p4.Egress.voting_table
table_feature0 = p4.Egress.table_feature0
table_feature1 = p4.Egress.table_feature1
table_feature2 = p4.Egress.table_feature2
table_feature3 = p4.Egress.table_feature3
table_feature4 = p4.Egress.table_feature4


code_table0 = p4.Egress.code_table0
code_table1 = p4.Egress.code_table1
code_table2 = p4.Egress.code_table2
code_table3 = p4.Egress.code_table3
code_table4 = p4.Egress.code_table4

table_feature0.add_with_SetCode0(feature0_start=0, feature0_end=182, code0=0b000, code1=0b00000, code2=0b000, code3=0b000, code4=0b000)
table_feature0.add_with_SetCode0(feature0_start=183, feature0_end=183, code0=0b000, code1=0b10000, code2=0b000, code3=0b000, code4=0b000)
table_feature0.add_with_SetCode0(feature0_start=184, feature0_end=229, code0=0b100, code1=0b11000, code2=0b000, code3=0b100, code4=0b100)
table_feature0.add_with_SetCode0(feature0_start=230, feature0_end=240, code0=0b100, code1=0b11100, code2=0b000, code3=0b100, code4=0b100)
table_feature0.add_with_SetCode0(feature0_start=241, feature0_end=254, code0=0b100, code1=0b11110, code2=0b100, code3=0b100, code4=0b110)
table_feature0.add_with_SetCode0(feature0_start=255, feature0_end=376, code0=0b100, code1=0b11110, code2=0b100, code3=0b110, code4=0b110)
table_feature0.add_with_SetCode0(feature0_start=377, feature0_end=384, code0=0b100, code1=0b11110, code2=0b110, code3=0b110, code4=0b110)
table_feature0.add_with_SetCode0(feature0_start=385, feature0_end=512, code0=0b110, code1=0b11111, code2=0b111, code3=0b111, code4=0b111)
table_feature0.add_with_SetCode0(feature0_start=513, feature0_end=65535, code0=0b111, code1=0b11111, code2=0b111, code3=0b111, code4=0b111)

table_feature1.add_with_SetCode1(feature1_start=0, feature1_end=7, code0=0b00, code1=0b00, code2=0b00, code3=0b000, code4=0b000)
table_feature1.add_with_SetCode1(feature1_start=8, feature1_end=8, code0=0b00, code1=0b00, code2=0b10, code3=0b100, code4=0b000)
table_feature1.add_with_SetCode1(feature1_start=9, feature1_end=10, code0=0b10, code1=0b10, code2=0b10, code3=0b110, code4=0b110)
table_feature1.add_with_SetCode1(feature1_start=11, feature1_end=65535, code0=0b11, code1=0b11, code2=0b11, code3=0b111, code4=0b111)

table_feature2.add_with_SetCode2(feature2_start=0, feature2_end=66, code0=0b00, code1=0b0, code2=0b00, code3=0b0, code4=0b00)
table_feature2.add_with_SetCode2(feature2_start=67, feature2_end=69, code0=0b10, code1=0b1, code2=0b00, code3=0b1, code4=0b00)
table_feature2.add_with_SetCode2(feature2_start=70, feature2_end=927, code0=0b10, code1=0b1, code2=0b10, code3=0b1, code4=0b10)
table_feature2.add_with_SetCode2(feature2_start=928, feature2_end=1917, code0=0b10, code1=0b1, code2=0b11, code3=0b1, code4=0b11)
table_feature2.add_with_SetCode2(feature2_start=1918, feature2_end=65535, code0=0b11, code1=0b1, code2=0b11, code3=0b1, code4=0b11)

table_feature3.add_with_SetCode3(feature3_start=0, feature3_end=3, code1=0b000, code2=0b0, code4=0b0)
table_feature3.add_with_SetCode3(feature3_start=4, feature3_end=4, code1=0b100, code2=0b0, code4=0b0)
table_feature3.add_with_SetCode3(feature3_start=5, feature3_end=5, code1=0b110, code2=0b1, code4=0b1)
table_feature3.add_with_SetCode3(feature3_start=6, feature3_end=65535, code1=0b111, code2=0b1, code4=0b1)

table_feature4.add_with_SetCode4(feature4_start=0, feature4_end=2, code0=0b0, code1=0b0, code2=0b0, code3=0b0)
table_feature4.add_with_SetCode4(feature4_start=3, feature4_end=65535, code0=0b1, code1=0b1, code2=0b1, code3=0b1)

print("******************* ENTERED FEATURE TABLE RULES *****************")

code_table0.add_with_SetClass0(codeword0= 0b00100000 , codeword0_mask= 0b00100000 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b00001000 , codeword0_mask= 0b00101000 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b10000000 , codeword0_mask= 0b10101001 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b00000000 , codeword0_mask= 0b10111001 , classe= 2 )
code_table0.add_with_SetClass0(codeword0= 0b00010000 , codeword0_mask= 0b10111001 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b00000011 , codeword0_mask= 0b00101011 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b00000001 , codeword0_mask= 0b00101111 , classe= 1 )
code_table0.add_with_SetClass0(codeword0= 0b00000101 , codeword0_mask= 0b01101111 , classe= 2 )
code_table0.add_with_SetClass0(codeword0= 0b01000101 , codeword0_mask= 0b01101111 , classe= 2 )

code_table1.add_with_SetClass1(codeword1= 0b000000100000 , codeword1_mask= 0b000000100000 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b000000000000 , codeword1_mask= 0b000000101101 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b010000001000 , codeword1_mask= 0b010000101101 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b000000000001 , codeword1_mask= 0b001000100101 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b000000001000 , codeword1_mask= 0b110000101101 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b100000011000 , codeword1_mask= 0b110000111101 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b001000000001 , codeword1_mask= 0b001010100101 , classe= 2 )
code_table1.add_with_SetClass1(codeword1= 0b001010000001 , codeword1_mask= 0b001010100101 , classe= 2 )
code_table1.add_with_SetClass1(codeword1= 0b100000001000 , codeword1_mask= 0b110001111101 , classe= 2 )
code_table1.add_with_SetClass1(codeword1= 0b100001001000 , codeword1_mask= 0b110001111101 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b000000000100 , codeword1_mask= 0b000100100100 , classe= 1 )
code_table1.add_with_SetClass1(codeword1= 0b000100000100 , codeword1_mask= 0b000100100110 , classe= 2 )
code_table1.add_with_SetClass1(codeword1= 0b000100000110 , codeword1_mask= 0b000100100110 , classe= 1 )

code_table2.add_with_SetClass2(codeword2= 0b000010000 , codeword2_mask= 0b000010010 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b000000100 , codeword2_mask= 0b000010110 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b000000000 , codeword2_mask= 0b100110110 , classe= 2 )
code_table2.add_with_SetClass2(codeword2= 0b000100000 , codeword2_mask= 0b100110110 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b100000000 , codeword2_mask= 0b101010110 , classe= 2 )
code_table2.add_with_SetClass2(codeword2= 0b101000000 , codeword2_mask= 0b101010110 , classe= 2 )
code_table2.add_with_SetClass2(codeword2= 0b000001010 , codeword2_mask= 0b000001010 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b000000010 , codeword2_mask= 0b000001011 , classe= 1 )
code_table2.add_with_SetClass2(codeword2= 0b000000011 , codeword2_mask= 0b010001011 , classe= 2 )
code_table2.add_with_SetClass2(codeword2= 0b010000011 , codeword2_mask= 0b010001011 , classe= 1 )

code_table3.add_with_SetClass3(codeword3= 0b00000100 , codeword3_mask= 0b00000100 , classe= 1 )
code_table3.add_with_SetClass3(codeword3= 0b00000010 , codeword3_mask= 0b11000110 , classe= 1 )
code_table3.add_with_SetClass3(codeword3= 0b00000000 , codeword3_mask= 0b11001110 , classe= 2 )
code_table3.add_with_SetClass3(codeword3= 0b00001000 , codeword3_mask= 0b11001110 , classe= 1 )
code_table3.add_with_SetClass3(codeword3= 0b01000000 , codeword3_mask= 0b01100100 , classe= 2 )
code_table3.add_with_SetClass3(codeword3= 0b01100000 , codeword3_mask= 0b01100100 , classe= 2 )
code_table3.add_with_SetClass3(codeword3= 0b10000000 , codeword3_mask= 0b11000101 , classe= 1 )
code_table3.add_with_SetClass3(codeword3= 0b10000001 , codeword3_mask= 0b11010101 , classe= 2 )
code_table3.add_with_SetClass3(codeword3= 0b10010001 , codeword3_mask= 0b11010101 , classe= 1 )

code_table4.add_with_SetClass4(codeword4= 0b000001000 , codeword4_mask= 0b000001001 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b000000010 , codeword4_mask= 0b000001011 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b100000000 , codeword4_mask= 0b110001011 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b000000000 , codeword4_mask= 0b110101011 , classe= 2 )
code_table4.add_with_SetClass4(codeword4= 0b000100000 , codeword4_mask= 0b110101011 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b010000000 , codeword4_mask= 0b011001011 , classe= 2 )
code_table4.add_with_SetClass4(codeword4= 0b011000000 , codeword4_mask= 0b011001011 , classe= 2 )
code_table4.add_with_SetClass4(codeword4= 0b000000101 , codeword4_mask= 0b000000101 , classe= 1 )
code_table4.add_with_SetClass4(codeword4= 0b000000001 , codeword4_mask= 0b000010101 , classe= 2 )
code_table4.add_with_SetClass4(codeword4= 0b000010001 , codeword4_mask= 0b000010101 , classe= 1 )

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


bfrt.mirror.cfg.entry_with_normal(sid=27,direction='BOTH',session_enable=True,ucast_egress_port=140,ucast_egress_port_valid=1,max_pkt_len=16384).push()

bfrt.mirror.cfg.entry_with_normal(sid=28,direction='BOTH',session_enable=True,ucast_egress_port=148,ucast_egress_port_valid=1,max_pkt_len=16384).push()


command_init = ['cd /root/bf-sde-9.6.0/ ; ./run_bfshell.sh --no-status-srv -f /home/C2_TLS/ucli_cmds'] 

def del_ports(port_list, file):
    for port_number in port_list:
        cmd = "pm port-del "+str(port_number)+"/- \n" 
        file.write(cmd)

def add_ports(port_list, file):
    for port_number in port_list:
        cmd = "pm port-add "+ str(port_number) + "/- 40G NONE \n"
        file.write(cmd)

def enb_ports(port_list, file):
    for port_number in port_list:
        cmd = "pm port-enb "+ str(port_number) + "/- \n"
        file.write(cmd)


def get_port_lsit(output):
    port_list = []
    lines = output.strip().split('\n')
    for line in lines:
        items = line.strip().split()
        if(len(items) > 3):
            try:
                if(int(items[0][0]) == 1):
                    status = items[3].strip().split("|")
                    if ("DWN" in status):
                        port_number = int(items[0][0])
                        port_list.append(port_number)
                else:
                    status = items[2].strip().split("|")
                    if ("DWN" in status):
                        port_number = int(items[0][0])
                        port_list.append(port_number)
            except Exception as e:
                pass
    return port_list

def check_ports(file):
    file.truncate(0)
    file.write("ucli\n")
    file.write("pm show\n")
    file.write("exit\nexit\n\n")


try:
    process = subprocess.Popen(command_init, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,shell=True)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        print("Command failed with exit code",process.returncode)

except Exception as e:
    print('An error occurred:', e)

time.sleep(10)

all_ports_up = False

command_check_ports = ['cd /root/bf-sde-9.6.0/ ; ./run_bfshell.sh --no-status-srv -f /home/C2_TLS/CP/ucli_check_ports']
command_update_config = ['cd /root/bf-sde-9.6.0/ ; ./run_bfshell.sh --no-status-srv -f /home/C2_TLS/CP/ucli_temp_cmds']

while (not all_ports_up):
    try:
        process = subprocess.Popen(command_check_ports, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,shell=True)
        stdout, stderr = process.communicate()
        port_list = get_port_lsit(stdout)
        if(len(port_list)==0):
            all_ports_up = True
            print("All ports are up")
        else:
            print("Re-enabling ports: ",port_list)
            file = open("/home/C2_TLS/CP/ucli_temp_cmds","w")
            file.write("ucli\n")
            
            del_ports(port_list,file)
            add_ports(port_list,file)
            enb_ports(port_list,file)

            file.write("pm show \n")
            file.write("exit\nexit\n\n")
            file.close()
            process = subprocess.Popen(command_update_config, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,shell=True)
            stdout, stderr = process.communicate()
            time.sleep(10)
        if process.returncode != 0:
            print("Command failed with exit code",process.returncode)
    
    except Exception as e:
        print('An error occurred:', e)

# forwarding = p4.Ingress.forwarding
# fine_grained = p4.Ingress.fine_grained
# coarse_grained = p4.Ingress.coarse_grained

# forwarding.clear()
# fine_grained.clear()
# coarse_grained.clear()

bfrt.complete_operations()
