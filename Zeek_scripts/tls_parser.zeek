module testing;

export {
    redef enum Log::ID += {tls_packet_lengths};
    type tls_records: record {
        tls_packet_lengths_record: vector of count &log;
    };
}
global packet_lengths: tls_records;
global tls_counter = 0;
global packet_sizes: table[string] of vector of count;

event zeek_init(){
    print ("Zeek starts here");
    Log::create_stream(testing::tls_packet_lengths, [$columns=tls_records]);
    local f=Log::get_filter(testing::tls_packet_lengths, "default");
    f$path = "infected_total";
    Log::add_filter(testing::tls_packet_lengths,f);
}

event tcp_packet(c: connection , is_orig: bool , flags: string , seq: count , ack: count , len: count , payload: string ){
    if(((c$id$resp_p == 443/tcp) || (c$id$orig_p == 443/tcp))  && bytestring_to_count(payload[0]) == 23){
        local total_length = |payload|;
        local start_index = 0;
        local end_index = bytestring_to_count(payload[3:5]);
        local loop_count = 0;
        # while((end_index <= total_length) && (loop_count < 5)){
        while(bytestring_to_count(payload[start_index]) !=0){
            if(bytestring_to_count(payload[start_index]) == 22){
                if((c$uid !in packet_sizes) && (bytestring_to_count(payload[start_index+5]) == 1)){
                    packet_sizes[c$uid] =  vector();
                    packet_sizes[c$uid][0] = bytestring_to_count(payload[start_index+3:start_index+5]); 
                }
                else if(bytestring_to_count(payload[start_index+5]) == 2){
                    packet_sizes[c$uid][1] = bytestring_to_count(payload[start_index+3:start_index+5]);
                }
                else if(bytestring_to_count(payload[start_index+5]) == 11){
                    packet_sizes[c$uid][2] = bytestring_to_count(payload[start_index+3:start_index+5]);
                }
                # else if(bytestring_to_count(payload[start_index+5]) == 12){
                #     packet_sizes[c$uid][3] = bytestring_to_count(payload[start_index+3:start_index+5]);
                #     print("Ali");
                # }
                # else if(bytestring_to_count(payload[start_index+5]) == 14){
                #     packet_sizes[c$uid][4] = bytestring_to_count(payload[start_index+3:start_index+5]);
                # }
                else if(bytestring_to_count(payload[start_index+5]) == 16){
                    packet_sizes[c$uid][3] = bytestring_to_count(payload[start_index+3:start_index+5]);
                }
                
                else if((|packet_sizes[c$uid]| == 4)){
                    packet_sizes[c$uid][4] = bytestring_to_count(payload[start_index+3:start_index+5]);
                    packet_lengths$tls_packet_lengths_record = packet_sizes[c$uid];
                    Log::write(testing::tls_packet_lengths, packet_lengths);
                    # print fmt("%s",packet_sizes[c$uid]);
                    # exit(1);
                }
            }

            start_index = end_index + 5;
            end_index = start_index + bytestring_to_count(payload[start_index+3:start_index+5]);
            loop_count+=1;
            
        }
    }
}


# event tcp_packet(c: connection , is_orig: bool , flags: string , seq: count , ack: count , len: count , payload: string ){
#     if(((c$id$resp_p == 443/tcp) || (c$id$orig_p == 443/tcp)) &&  (bytestring_to_count(payload[0]) == 22)){
#         tls_counter +=1;
#         print fmt("The payload is %s", payload);
#         if(tls_counter == 5){
#             exit(1);
#         }
#     }
# }

event zeek_done(){
    print("Zeek ends here");
}