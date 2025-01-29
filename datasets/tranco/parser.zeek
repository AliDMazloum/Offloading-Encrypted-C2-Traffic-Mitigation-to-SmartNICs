module testing;

export {
    redef enum Log::ID += {tls_flow_stats};
    type stats: record {
        tls_flows: double &default=0 &log;
        packets_parsed_in_P4: double &default=0 &log;
        packets_parsed_in_DPDK: double &default=0 &log;
        packet_ratio: double &log;
        bytes_parsed_in_P4: double &default=0 &log;
        bytes_parsed_in_DPDK: double &default=0 &log;
        bytes_ratio: double &log;
    };
}
global tls_stats: stats;
global tls_counter = 0;
global packet_sizes: table[string] of vector of count;
global recorded_flows:  table[string] of bool &default=F;

event zeek_init(){
    Log::create_stream(testing::tls_flow_stats, [$columns=stats]);
    local f=Log::get_filter(testing::tls_flow_stats, "default");
    f$path = "shuf_tranco004_tls13_2024_01_30_13h29";
    Log::add_filter(testing::tls_flow_stats,f);
}

event connection_established(c: connection){
    tls_stats$tls_flows +=1;
}


event tcp_packet(c: connection , is_orig: bool , flags: string , seq: count , ack: count , len: count , payload: string ){
    tls_stats$packets_parsed_in_P4 +=1;
    tls_stats$bytes_parsed_in_P4 +=len;
    if(((c$id$resp_p == 443/tcp) || (c$id$orig_p == 443/tcp))){
        local start_index = 0;
        if((c$uid !in packet_sizes) && (bytestring_to_count(payload[start_index+5]) == 1) && (bytestring_to_count(payload[start_index]) == 22)){ #Cleint Hello
            tls_stats$packets_parsed_in_DPDK +=1;
            tls_stats$bytes_parsed_in_DPDK +=len;
        }
        if((bytestring_to_count(payload[start_index+5]) == 2) && (bytestring_to_count(payload[start_index]) == 22) ){ #Server Hello
            tls_stats$packets_parsed_in_DPDK +=1;
            tls_stats$bytes_parsed_in_DPDK +=len;
        }
    }
}

event zeek_done(){
    tls_stats$packet_ratio = (tls_stats$packets_parsed_in_DPDK / tls_stats$packets_parsed_in_P4) * 100;
    tls_stats$bytes_ratio = (tls_stats$bytes_parsed_in_DPDK / tls_stats$bytes_parsed_in_P4) * 100;
    Log::write(testing::tls_flow_stats, tls_stats);
}
