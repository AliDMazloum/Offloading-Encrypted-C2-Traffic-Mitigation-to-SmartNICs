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
        # print(dirpath)
        directories.append(dirpath)
        # directories.append(str(Path(dirpath).resolve()))   

def reply_pcaps(directory):

    if not os.path.isdir(directory):
        print(f"The directory {directory} does not exist.")
    else:
        pcap_files = [f for f in os.listdir(directory) if f.endswith('.pcap')]
    
    for pcap_file in pcap_files:
        pcap_file_path = os.path.join(directory, pcap_file)

        result = subprocess.run([
            "tcpreplay-edit", 
            "--mtu=1400", 
            "--mtu-trunc", 
            "-i", "eth1", 
            "--mbps=10000", 
            pcap_file_path
        ])
        if result.returncode != 0:
            print(f"Error processing {pcap_file}.")
        else:
            print(f"Successfully processed {pcap_file}.")


for directory in directories:
    reply_pcaps(directory)
