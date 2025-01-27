import os
import subprocess
import argparse
from pathlib import Path

parser = argparse.ArgumentParser(description="Generate and run Zeek scripts on .pcap files in a directory.")
parser.add_argument('directory', type=str, help="Directory containing .pcap files.")
parser.add_argument('zeek_file', type=str, help="zeek script to apply on pcap files.")
args = parser.parse_args()

root_dir = args.directory
zeek_file = args.zeek_file

with open(zeek_file, 'r') as f:
    zeek_script = f.read()

directories = []
for dirpath, dirnames, filenames in os.walk(root_dir):
    dirnames[:] = [d for d in dirnames if d != "zeek_logs"]
    if any(file.endswith('.pcap') for file in filenames):
        directories.append(str(Path(dirpath).resolve()))

for dir in directories:
    print(dir)
# print(directories)
exit(1)

def generate_logs(directory, zeek_script):
    zeek_files_dir = os.path.join(directory,"/zeek_logs")
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
                except subprocess.CalledProcessError as e:
                    print(f"Error running Zeek on {pcap_file}: {e}")


for directory in directories:
    generate_logs(directory,zeek_script)