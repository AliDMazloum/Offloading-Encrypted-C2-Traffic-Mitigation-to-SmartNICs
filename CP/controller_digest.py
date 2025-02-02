#!/usr/bin/python3

import os
import sys

# Add Python3 to the path
SDE_INSTALL   = os.environ['SDE_INSTALL']
print(SDE_INSTALL)
SDE_PYTHON2   = os.path.join(SDE_INSTALL, 'lib', 'python2.7', 'site-packages')
sys.path.append(SDE_PYTHON2)
sys.path.append(os.path.join(SDE_PYTHON2, 'tofino'))

PYTHON3_VER   = '{}.{}'.format(
                    sys.version_info.major,
                    sys.version_info.minor)
SDE_PYTHON3   = os.path.join(SDE_INSTALL, 'lib', 'python' + PYTHON3_VER, 'site-packages')
sys.path.append(SDE_PYTHON3)
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino'))
sys.path.append(os.path.join(SDE_PYTHON3, 'tofino', 'bfrt_grpc'))

import bfrt_grpc.client as bfrt_client
import socket, struct

filename_out = sys.argv[1] #output csv file with classification results
Actual_class = sys.argv[2] #the actual classification

# Connect to the BF Runtime Server
interface = bfrt_client.ClientInterface(
    grpc_addr = '0.0.0.0:50052',
    client_id = 1,
    device_id = 0)
print('Connected to BF Runtime Server')


# Get the information about the running program
bfrt_info = interface.bfrt_info_get()
print('The target runs the program ', bfrt_info.p4_name_get())

# Establish that we are using this program on the given connection
interface.bind_pipeline_config(bfrt_info.p4_name_get())

# Get digest
learn_filter = bfrt_info.learn_get("digest_flow_class")
learn_filter_1 = bfrt_info.learn_get("digest_client_hellow")
# learn_filter_2 = bfrt_info.learn_get("digest_detected_flow")


target = bfrt_client.Target(device_id=0, pipe_id=0xffff)

# header = 'flow_ID rev_flow_ID src_ip dst_ip src_port dst_port client_hello_len, client_hello_exts_number, server_hello_len, server_hello_exts_number,tls_version'

header = 'Actual Pridected'

with open(filename_out, "w") as text_file:
    text_file.write(header)
    text_file.write("\n")

while True:
    try:
        digest = interface.digest_get(timeout=400)
    except:
        f = open("x.txt", "a")
        f.write('---- \n')
        f.close()
        break

    recv_target = digest.target

    data_list = learn_filter.make_data_list(digest)
    digest_type = 1
            

    if digest_type == 1:
        keys_table = []
        datas_table = []
        for dd in data_list:
            data_dict = dd.to_dict()

            flow_id = str(data_dict['flow_ID'])
            rev_flow_id = str(data_dict['rev_flow_ID'])
            source_addr = socket.inet_ntoa(struct.pack('!L', data_dict['src_addr']))
            destin_addr = socket.inet_ntoa(struct.pack('!L', data_dict['dst_addr']))
            source_port = str(data_dict['src_port'])
            destin_port = str(data_dict['dst_port'])
            client_hello_len = str(data_dict["client_hello_len"])
            client_hello_exts_number = str(data_dict["client_hello_exts_number"])
            server_hello_len = str(data_dict["server_hello_len"])
            server_hello_exts_number = str(data_dict["server_hello_exts_number"])
            tls_version = str(data_dict["tls_version"])
            flow_packet_class = str(data_dict['class_value'])
            #
            # FlowID =  source_addr + " " + destin_addr + " " + source_port + " " + destin_port + " " + protocol + " " + flow_packet_class            

            ouptut_string = flow_id+ ", " +rev_flow_id+ ", " +source_addr + ', ' + destin_addr + ', ' + source_port\
            + ', ' + destin_port+", "+ client_hello_len+ ", " + client_hello_exts_number+ ", " + server_hello_len+ ", " +\
            server_hello_exts_number+ ", " +tls_version+ ", " + flow_packet_class

            ouptut_string = client_hello_len+ ", " + client_hello_exts_number+ ", " + server_hello_len+ ", " +\
            server_hello_exts_number+ ", " +tls_version+ ", " + flow_packet_class

            with open(filename_out, "a") as text_file:
                    text_file.write(Actual_class +" " +flow_packet_class)
                    text_file.write("\n")
