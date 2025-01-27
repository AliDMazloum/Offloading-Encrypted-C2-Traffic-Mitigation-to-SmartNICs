import os
import subprocess
import argparse
import sys
from pathlib import Path

parser = argparse.ArgumentParser(description="Generate and run Zeek scripts on .pcap files in a directory.")
parser.add_argument('directory', type=str, help="Directory containing .pcap files.")
parser.add_argument('zeek_file', type=str, help="zeek script to apply on pcap files.")
# parser.add_argument('version',default=None, type=int, help="TLS version.")
args = parser.parse_args()

# directory = args.directory
working_directory = Path().resolve()

root_dir = args.directory
zeek_file = args.zeek_file

with open(zeek_file, 'r') as f:
    zeek_script = f.read()

directories = []
for dirpath, dirnames, _ in os.walk(root_dir):
    abs_path = os.path.join(working_directory,dirpath)
    for dir in dirnames:
        include_dir = False
        for _, _, filenames in os.walk(dir):
            if ".pcap" in filenames:
                include_dir = True
                break
        if("zeek_logs" != dir and include_dir):
            directories.append(os.path.join(abs_path,dir))

print(directories)

def generate_logs(directory, zeek_script):
    zeek_files_dir = directory+"/zeek_logs"
    Path(zeek_files_dir).mkdir(parents=True, exist_ok=True)

    if not os.path.isdir(directory):
        print(f"The directory {directory} does not exist.")
    else:
        pcap_files12 = [f for f in os.listdir(directory) if f.endswith('.pcap') and (("tls12" in f or "capture" in f) or ("1.2" in directory))]

        pcap_files13 = [f for f in os.listdir(directory) if f.endswith('.pcap') and (("tls13" in f or "capture" in f) or ("1.2" in directory))]

        if not pcap_files12 and not pcap_files13:
            print("No .pcap files found in the directory.")
        else:
            zeek_script_template = zeek_script
            
            zeek_script_filename = os.path.join(directory, "parser.zeek")
            print(f"Created Zeek script for {directory}: {zeek_script_filename}")

            for pcap_file in pcap_files12:
                pcap_file_name = os.path.splitext(pcap_file)[0]
                modified_script = zeek_script_template.replace("{pcap_file_name}", pcap_file_name)
                tls_version = "2"
                modified_script = modified_script.replace("{tls_version}", str(tls_version))
                zeek_script_filename = os.path.join(directory, "parser.zeek")
                with open(zeek_script_filename, 'w') as script_file:
                    script_file.write(modified_script)
                
                os.chdir(zeek_files_dir)
                command = ["/opt/zeek/bin/zeek", "-r", os.path.join(directory, pcap_file), zeek_script_filename,"-Cb"]
                try:
                    subprocess.run(command, check=True)
                    print(f"Successfully ran Zeek on {pcap_file}")
                except subprocess.CalledProcessError as e:
                    print(f"Error running Zeek on {pcap_file}: {e}")
            
            for pcap_file in pcap_files13:
                pcap_file_name = os.path.splitext(pcap_file)[0]
                modified_script = zeek_script_template.replace("{pcap_file_name}", pcap_file_name)
                tls_version = "3"
                modified_script = modified_script.replace("{tls_version}", tls_version)
                zeek_script_filename = os.path.join(directory, "parser.zeek")
                with open(zeek_script_filename, 'w') as script_file:
                    script_file.write(modified_script)

                os.chdir(zeek_files_dir)
                command = ["/opt/zeek/bin/zeek", "-r", os.path.join(directory, pcap_file), zeek_script_filename,"-Cb"]
                try:
                    subprocess.run(command, check=True)
                    print(f"Successfully ran Zeek on {pcap_file}")
                except subprocess.CalledProcessError as e:
                    print(f"Error running Zeek on {pcap_file}: {e}")


for directory in directories:
    generate_logs(directory,zeek_script)