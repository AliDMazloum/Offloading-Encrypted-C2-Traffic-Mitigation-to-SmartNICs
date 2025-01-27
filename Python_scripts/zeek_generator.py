import os
import subprocess
import argparse
import sys

parser = argparse.ArgumentParser(description="Generate and run Zeek scripts on .pcap files in a directory.")
parser.add_argument('directory', type=str, help="Directory containing .pcap files.")
parser.add_argument('version',default=None, type=int, help="TLS version.")
args = parser.parse_args()

directory = args.directory
if args.version:
    tls_version = args.version
else:
    tls_version = 2

if not os.path.isdir(directory):
    print(f"The directory {directory} does not exist.")
else:
    pcap_files12 = [f for f in os.listdir(directory) if f.endswith('.pcap') and ("tls12" in f or "capture" in f)]

    pcap_files13 = [f for f in os.listdir(directory) if f.endswith('.pcap') and ("tls13" in f or "capture" in f)]

    if not pcap_files12 and not pcap_files13:
        print("No .pcap files found in the directory.")
    else:
        zeek_script_template = """module testing;

export {
    redef enum Log::ID += {tls_packet_lengths};
    type tls_records: record {
        # src_ip: addr &log;
        # dst_ip: addr &log;
        # src_port: port &log;
        # dst_port: port &log;
        tls_packet_lengths_record: vector of count &log;
    };
}
global packet_lengths: tls_records;
global tls_counter = 0;
global packet_sizes: table[string] of vector of count;
global established_flows:  table[string] of bool &default=F;
global recorded_flows:  table[string] of bool &default=F;

event zeek_init(){
    print ("Zeek starts here");
    Log::create_stream(testing::tls_packet_lengths, [$columns=tls_records]);
    local f=Log::get_filter(testing::tls_packet_lengths, "default");
    f$path = "{pcap_file_name}";
    Log::add_filter(testing::tls_packet_lengths,f);
}

event connection_established(c: connection){
    established_flows[c$uid] = T;
}


event tcp_packet(c: connection , is_orig: bool , flags: string , seq: count , ack: count , len: count , payload: string ){
    if(((c$id$resp_p == 443/tcp) || (c$id$orig_p == 443/tcp))  && established_flows[c$uid] == T){
        local start_index = 0;
        local end_index = bytestring_to_count(payload[3:5]);
        local record_length = 0;
        local number_of_extensions = 0;
        local current_index = 0;
        local session_length = 0;
        local cipher_suites_length = 0;
        local compression_method_length = 0;
        local extensions_length = 0;
        local extension_length = 0;
        if(c$uid !in packet_sizes ){
            if((c$uid !in packet_sizes) && (bytestring_to_count(payload[start_index+5]) == 1) && (bytestring_to_count(payload[start_index]) == 22)){ #Cleint Hello
                record_length = bytestring_to_count(payload[3:5]); #Extract the record length
                
                start_index+=6; # Add the length till handshake type
                start_index+=4; # Add the length directly before the Random
                start_index +=33; # Add the length directly before the Seesion length

                session_length = bytestring_to_count(payload[start_index]);
                start_index +=1; # Add the length directly before the Seesion length
                start_index +=session_length; # Add the length directly before the Seesion length

                cipher_suites_length = bytestring_to_count(payload[start_index:start_index+2]);
                start_index +=2; # Add the length directly before the cipher suites
                start_index +=cipher_suites_length; # Add the length directly before the compression methods length

                compression_method_length = bytestring_to_count(payload[start_index]);
                start_index +=1; # Add the length directly before the compression methods
                start_index +=compression_method_length; # Add the length directly before the extensions lengths

                extensions_length = bytestring_to_count(payload[start_index:start_index+2]);
                start_index +=2; # Add the length directly before the first extension

                while (current_index < extensions_length){
                    number_of_extensions +=1;
                    start_index +=2; # Add the length to reach the extension length
                    extension_length = bytestring_to_count(payload[start_index:start_index+2]);
                    start_index +=(2+extension_length); # Add the length to reach the extension length
                    current_index+=(4+extension_length);
                }
                
                packet_sizes[c$uid] =  vector();
                recorded_flows[c$uid] = T;
                packet_sizes[c$uid][0]= record_length;
                packet_sizes[c$uid][1]= number_of_extensions;
            }
        }
        else if(|packet_sizes[c$uid]| == 2){
            if((bytestring_to_count(payload[start_index+5]) == 2) && (bytestring_to_count(payload[start_index]) == 22) ){ #Server Hello
                record_length = bytestring_to_count(payload[3:5]); #Extract the record length

                start_index+=6; # Add the length till handshake type
                start_index+=4; # Add the length directly before the Random
                start_index +=33; # Add the length directly before the Seesion length

                session_length = bytestring_to_count(payload[start_index]);
                start_index +=1; # Add the length directly before the Seesion length
                start_index +=session_length; # Add the length directly before the Seesion length

                start_index +=2; # Add the length directly before the compression methods length

                start_index +=1; # Add the length directly before the extensions lengths

                extensions_length = bytestring_to_count(payload[start_index:start_index+2]);
                start_index +=2; # Add the length directly before the first extension

                while (current_index < extensions_length){
                    number_of_extensions +=1;
                    start_index +=2; # Add the length to reach the extension length
                    extension_length = bytestring_to_count(payload[start_index:start_index+2]);
                    start_index +=(2+extension_length); # Add the length to reach the extension length
                    current_index+=(4+extension_length);
                }
                packet_sizes[c$uid][2]= record_length;
                packet_sizes[c$uid][3]= number_of_extensions;
                packet_sizes[c$uid][4]= {tls_version};
                packet_lengths$tls_packet_lengths_record = packet_sizes[c$uid];
                Log::write(testing::tls_packet_lengths, packet_lengths);
            }
        }
    }
}

event zeek_done(){
    print("Zeek ends here");
}
"""

        for pcap_file in pcap_files12:
            pcap_file_name = os.path.splitext(pcap_file)[0]
            modified_script = zeek_script_template.replace("{pcap_file_name}", pcap_file_name)
            modified_script = modified_script.replace("{tls_version}", str(tls_version))
            zeek_script_filename = os.path.join(directory, "parser.zeek")
            with open(zeek_script_filename, 'w') as script_file:
                script_file.write(modified_script)

            print(f"Created Zeek script for {pcap_file_name}: {zeek_script_filename}")

            os.chdir(directory)
            command = ["/opt/zeek/bin/zeek", "-r", os.path.join(directory, pcap_file), zeek_script_filename,"-Cb"]
            try:
                subprocess.run(command, check=True)
                print(f"Successfully ran Zeek on {pcap_file}")
            except subprocess.CalledProcessError as e:
                print(f"Error running Zeek on {pcap_file}: {e}")
        
        for pcap_file in pcap_files13:
            pcap_file_name = os.path.splitext(pcap_file)[0]
            modified_script = zeek_script_template.replace("{pcap_file_name}", pcap_file_name)
            modified_script = modified_script.replace("{tls_version}", str(3))
            zeek_script_filename = os.path.join(directory, "parser.zeek")
            with open(zeek_script_filename, 'w') as script_file:
                script_file.write(modified_script)

            print(f"Created Zeek script for {pcap_file_name}: {zeek_script_filename}")

            os.chdir(directory)
            command = ["/opt/zeek/bin/zeek", "-r", os.path.join(directory, pcap_file), zeek_script_filename,"-Cb"]
            try:
                subprocess.run(command, check=True)
                print(f"Successfully ran Zeek on {pcap_file}")
            except subprocess.CalledProcessError as e:
                print(f"Error running Zeek on {pcap_file}: {e}")
