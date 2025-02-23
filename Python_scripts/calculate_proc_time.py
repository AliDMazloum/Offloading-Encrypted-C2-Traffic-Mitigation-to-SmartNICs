import os
import subprocess
import argparse
from pathlib import Path
from time import sleep

parser = argparse.ArgumentParser(description="Generate and run Zeek scripts on .pcap files in a directory.")
parser.add_argument('directory', type=str, help="Directory containing .pcap files.")

args = parser.parse_args()

root_dir = args.directory

directories = []
for dirpath, dirnames, filenames in os.walk(root_dir):
    if any(file.endswith('.pcap') for file in filenames):
        directories.append(dirpath)

def generate_logs(directory):
    proc_logs_dir = directory+"/proc_logs_20Gbps"
    try:
        os.system(f"sudo ssh -t root@172.168.1.2 'cd /home/C2_TLS/; mkdir {proc_logs_dir}'")
    except:
        print("Classification logs directory cannot be created")

    if not os.path.isdir(directory):
        print(f"The directory {directory} does not exist.")
    else:
        pcap_files = [f for f in os.listdir(directory) if f.endswith('.pcap')]
    
    for pcap_file in pcap_files:
        os.system(f"sudo ssh -t root@172.168.1.2 'cd /home/C2_TLS;. /root/tools/set_sde.bash; pkill -f controller_digest'")
        stats_file = pcap_file[:-5]+".csv"
        stats_file = proc_logs_dir +"/"+stats_file

        os.system(f"sudo ssh -t root@172.168.1.2 'cd /home/C2_TLS;. /root/tools/set_sde.bash; touch {stats_file};\
                    python CP/controller_digest.py {stats_file}' &")
        
        sleep(0.5)

        pcap_file_path = os.path.join(directory, pcap_file)

        result = subprocess.run([
            "tcpreplay-edit", 
            "--mtu=1400", 
            "--mtu-trunc", 
            "-i", "eth1", 
            "--mbps=2000", 
            pcap_file_path
        ])
        if result.returncode != 0:
            print(f"Error processing {pcap_file}.")
        else:
            print(f"Successfully processed {pcap_file}.")


for directory in directories:
    generate_logs(directory)
