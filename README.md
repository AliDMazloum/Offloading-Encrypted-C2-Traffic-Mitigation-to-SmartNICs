# Data processing for offline training 
    Zeek_scripts contains the scripts used to parse the PCAP files.
        - TLS_behav.zeek processes PCAP files and extract the features for the offline training
        - TLS_flow_stats.zeek processes the PCAP files and calculates the discribution of packets processed by P4 and those processed by DPDK
        
        # Running scripts
            - sudo pthon3 Python_scripts/zeek_generator.py <path_to_dataset_directory> <path_to_zeek_script>

