# Offloading-Encrypted-C2-Traffic-Mitigation-to-SmartNICs
    This directory contains the source code of paper Toward Fingerprinting C2 traffic in the Pata Plane. The code can be divided as follows:

        Zeek_scripts/ contains the scripts used to parse the PCAP files.
            - TLS_behav.zeek processes PCAP files and extract the features for the offline training
            - TLS_flow_stats.zeek processes the PCAP files and calculates the discribution of packets processed by P4 and those processed by DPDK
            
        Python_scripts/ contains the scripts to run Zeek scripts and generate P4 rules
            - zeek_generator.py <path_to_dataset_directory> <path_to_zeek_script> : this python script runs the zeek script over the dataset and    generate the result in a directory zeek_logs
            - generate_table_entries.py: this python script generates the table entries for the P4 application based on the "RF.pkl" file