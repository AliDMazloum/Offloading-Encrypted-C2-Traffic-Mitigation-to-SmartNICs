module testing;

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
    f$path = "shuf_tranco000_tls12_2024_01_30_12h40";
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
                record_length = bytestring_to_count(payload[6:9]); #Extract the record length
                
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
                record_length = bytestring_to_count(payload[6:9]); #Extract the record length

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
                packet_sizes[c$uid][4]= 2;
                packet_lengths$tls_packet_lengths_record = packet_sizes[c$uid];
                Log::write(testing::tls_packet_lengths, packet_lengths);
            }
        }
    }
}

event zeek_done(){
    print("Zeek ends here");
}

# event tcp_packet(c: connection , is_orig: bool , flags: string , seq: count , ack: count , len: count , payload: string ){
#     if(((c$id$resp_p == 443/tcp) || (c$id$orig_p == 443/tcp))  && bytestring_to_count(payload[0]) == 22){
#         local total_length = |payload|;
#         local start_index = 0;
#         local end_index = bytestring_to_count(payload[3:5]);
#         local loop_count = 0;
#         while(bytestring_to_count(payload[start_index]) !=0){
#             if(bytestring_to_count(payload[start_index]) == 22){
#                 if((c$uid !in packet_sizes) && (bytestring_to_count(payload[start_index+5]) == 1)){ #Cleint Hello
#                     packet_sizes[c$uid] =  vector();
#                     packet_sizes[c$uid][0] = bytestring_to_count(payload[start_index+3:start_index+5]); 
#                 }
#                 else if(bytestring_to_count(payload[start_index+5]) == 2){ #Server Hello
#                     packet_sizes[c$uid][1] = bytestring_to_count(payload[start_index+3:start_index+5]);
#                 }
#                 else if(bytestring_to_count(payload[start_index+5]) == 11){ #Certificate
#                     packet_sizes[c$uid][2] = bytestring_to_count(payload[start_index+3:start_index+5]);
#                 }
#                 else if(bytestring_to_count(payload[start_index+5]) == 12){ #Server Key Exchange
#                     packet_sizes[c$uid][3] = bytestring_to_count(payload[start_index+3:start_index+5]);
#                 }
#                 else if(bytestring_to_count(payload[start_index+5]) == 14){ #Server Hello Done
#                     packet_sizes[c$uid][4] = bytestring_to_count(payload[start_index+3:start_index+5]);
#                 }
#                 else if(bytestring_to_count(payload[start_index+5]) == 16){ #Cleint Key Exchange
#                     packet_sizes[c$uid][5] = bytestring_to_count(payload[start_index+3:start_index+5]);
#                     packet_lengths$tls_packet_lengths_record = packet_sizes[c$uid];
#                     Log::write(testing::tls_packet_lengths, packet_lengths);
#                 }
            
#             }

#             start_index = end_index + 5;
#             end_index = start_index + bytestring_to_count(payload[start_index+3:start_index+5]);
#             loop_count+=1;
            
#         }
#     }
# }