from ipaddress import ip_address
import threading
import subprocess
import os
import time

p4 = bfrt.basic.pipe


command_init = ['cd /root/bf-sde-9.6.0/ ; ./run_bfshell.sh --no-status-srv -f /home/TLS_parser/ucli_cmds'] 

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

command_check_ports = ['cd /root/bf-sde-9.6.0/ ; ./run_bfshell.sh --no-status-srv -f /home/TLS_parser/CP/ucli_check_ports']
command_update_config = ['cd /root/bf-sde-9.6.0/ ; ./run_bfshell.sh --no-status-srv -f /home/TLS_parser/CP/ucli_temp_cmds']

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
            file = open("/home/TLS_parser/CP/ucli_temp_cmds","w")
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

bfrt.mirror.cfg.entry_with_normal(sid=27,direction='BOTH',session_enable=True,ucast_egress_port=140,ucast_egress_port_valid=1,max_pkt_len=16384).push()

bfrt.mirror.cfg.entry_with_normal(sid=28,direction='BOTH',session_enable=True,ucast_egress_port=148,ucast_egress_port_valid=1,max_pkt_len=16384).push()


# Forwarding based on IP address
# forwarding.add_with_send_using_port(dst_addr=ip_address("192.168.0.1"), port=132)
# forwarding.add_with_send_using_port(dst_addr=ip_address("192.168.0.2"), port=140)
# forwarding.add_with_send_using_port(dst_addr=ip_address("192.168.0.3"), port=148)


# Example 1: Adding a rule to the fine-grained monitoring. Sending "facebook.com" through port 3
# Using CP.py, we can get the P4-based CRC32C hash of facebook.com: 0x74aca149
# fine_grained.add_with_send_using_port(servername_hash32="0x74aca149", port=3) 

# Todo: Example 2: Adding a rule to the coarse-grained monitoring. Check Meta4 (DNS parsing P4) github.

bfrt.complete_operations()

# # Final programming
# print("""
# ******************* PROGAMMING RESULTS *****************
# """)
# print ("Table forwarding:")
# forwarding.dump(table=True)
