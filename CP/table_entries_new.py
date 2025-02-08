from netaddr import IPAddress
import subprocess
import time

p4 = bfrt.basic.pipe

command_init = ['cd /root/bf-sde-9.6.0/ ; ./run_bfshell.sh --no-status-srv -f /home/C2_TLS/ucli_cmds'] 

def del_ports(port_list, file):
    for port_number in port_list:
        cmd = "pm port-del "+str(port_number)+"/- \n" 
        file.write(cmd)

def add_ports(port_list, file):
    for port_number in port_list:
        if(port_number == 3):
            cmd = "pm port-add "+ str(port_number) + "/- 100G RS \n"
        else:
            cmd = "pm port-add "+ str(port_number) + "/- 100G NONE \n"
        file.write(cmd)

def enb_ports(port_list, file):
    for port_number in port_list:
        cmd = "pm port-enb "+ str(port_number) + "/- \n"
        file.write(cmd)


def get_port_lsit(output):
    port_list = []
    lines = output.strip().split('\n')
    lines = lines[1:]
    for line in lines:
        items = line.strip().split("|")
        try:
            status = items[10]
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

bfrt.complete_operations()
