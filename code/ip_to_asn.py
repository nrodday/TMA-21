__author__ = "Nils Rodday"
__copyright__ = "Copyright 2019"
__credits__ = ["Nils Rodday"]
__email__ = "nils.rodday@unibw.de"
__status__ = "Experimental"

# Get input list from https://ftp.ripe.net/ripe/atlas/probes/archive/2019/10/

import sys
import argparse
import json
import subprocess
import shlex
import struct
import socket
import pyasn
from datetime import date
import subprocess
from os import listdir
from os.path import isfile, join
import Atlas_rov_identification
from scapy.all import *

def parse_arguments(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="IP to ASN mapping file (Cache)")
    return parser.parse_args(args)

def read_cache_file(ip_to_asn_file):
    with open(ip_to_asn_file, "r") as read_file:
        file = json.load(read_file)
    return file

def read_to_dict_from_cymru_data(cymru_response, ip_to_asn):
    #ip_to_asn["1.2.3.4"] = "AS1234"
    found_ips = set()

    with open(cymru_response, "r") as write_file:
        for i in write_file:
            if i.startswith("Bulk mode"): continue
            line = i.split("|")
            #print(line[0], line[1])
            if line[0].strip() != "NA":
                ip = line[1].strip()
                ip_to_asn[ip]=line[0].strip()
                found_ips.add(ip)

    return ip_to_asn, found_ips

def extract_all_ips(traceroute):
    ips = set()

    for day in traceroute:
        print("DAY: ", day)
        for id in traceroute[day]:
            #print(id)
            for probe in traceroute[day][id]:
                for hop in probe['result']:
                    try: #sometimes result looks like: {'error': 'name resolution failed: non-recoverable failure in name resolution (1)'}
                        for result in hop["result"]:
                            try: #Sometimes there is no from but instead on "x: *"
                                ips.add(result["from"])
                            except:
                                pass
                    except:
                        pass

    return ips

def write_cymru_file(ips, file):
    with open(file, "w") as write_file:
        write_file.write("begin\n")
        for ip in ips:
            write_file.write(ip + "\n")
        write_file.write("end\n")

def send_to_cymru(cymru_request, cymru_response):
    # This queries Team Cymru accrording to https://team-cymru.com/community-services/ip-asn-mapping/
    # It is not handling any errors!
    command = 'netcat whois.cymru.com 43 < ' + cymru_request + ' | sort -n > ' + cymru_response
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.communicate()

def perform_lookup(ip):
    ip_chunks = ip.split(".")
    cmd = "dig +short " + ip_chunks[3] + "." + ip_chunks[2] + "." + ip_chunks[1] + "." + ip_chunks[0] + ".origin.asn.cymru.com TXT"
    proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE)
    out, err = proc.communicate()

    if err != None:
        print("Some Error occurred during the DNS query towards Team Cymru!")
    else:
        decoded = out.decode("utf-8")
        asn = decoded.split(" ")[0].replace("\"","")
    return asn

def update_mapping_cache(ip_to_asn_file, ip_to_asn):
    with open(ip_to_asn_file, "w") as write_file:
        json.dump(ip_to_asn, write_file)

def write_missing_ips_to_file(ips, timestamp):
    with open('Atlas/pyasn/'+timestamp+'missing_ips', 'w') as write_file:
        write_file.write('begin\n')
        for ip in ips:
            write_file.write(ip+"\n")
        write_file.write('end\n')

def resolve_private_ips(ips, ip_to_asn):
    #
    # THE FOLLOWING PART IS FOR MISSING IPS AND OVERWRITING IPS WHICH ARE FROM A PRIVATE ADDRESS RANGE
    #

    prefix_1 = "10.0.0.0/8"
    prefix_2 = "172.16.0.0/12"
    prefix_3 = "192.168.0.0/16"
    prefix_4 = "100.64.0.0/10" #CGNAT range

    remaining = len(ips)
    missing_ips = set()
    found_ips = set()
    overwritten_ips = set()
    tmp_ips = ips.copy()
    for ip in ips:
        remaining -= 1
        if ip not in ip_to_asn:
            missing_ips.add(ip)
            if ip_in_prefix(ip, prefix_1) or ip_in_prefix(ip, prefix_2) or ip_in_prefix(ip, prefix_3) or ip_in_prefix(ip, prefix_4):
                ip_to_asn[ip] = "private"
                found_ips.add(ip)
                tmp_ips.remove(ip)
        else:
            if ip_in_prefix(ip, prefix_1) or ip_in_prefix(ip, prefix_2) or ip_in_prefix(ip, prefix_3) or ip_in_prefix(ip, prefix_4):
                ip_to_asn[ip] = "private"
                overwritten_ips.add(ip)
                tmp_ips.remove(ip)

    print()
    print("PRIVATE IPs TRANSLATION")
    print("Missing ips: ", len(missing_ips))
    print("Newly found ips: ", len(found_ips))
    print("Overwritten ips: ", len(overwritten_ips))
    print("First, dataset size: ", len(ip_to_asn))
    print()

    return ip_to_asn, tmp_ips

def resolve_pyasn_ips(ips, ip_to_asn):
    # Read all RIBs, load ASNDBs in PyASN
    updated_ribs = 'Atlas/pyasn/updated_ribs/'
    onlyfiles = [join(updated_ribs, f) for f in listdir(updated_ribs) if isfile(join(updated_ribs, f))]
    asndb_1 = asndb_2 = asndb_3 = asndb_4 = asndb_5 = asndb_6 = asndb_7 = asndb_8 = ''
    asndbs = [asndb_1,asndb_2,asndb_3,asndb_4,asndb_5,asndb_6,asndb_7,asndb_8]

    print()
    print('Reading PyASN DB')
    for i in range(0,len(asndbs)):
        print(onlyfiles[i])
        asndbs[i] = pyasn.pyasn(onlyfiles[i]) # pyasn.pyasn('Atlas/pyasn/linx_rib.20200213.1600.dat')

    remaining = len(ips)
    missing_ips = set()
    found_ips = set()
    for ip in ips:
        remaining -= 1
        #print(remaining)
        if ip not in ip_to_asn:
            missing_ips.add(ip)
            #new_mapping = perform_cymru_lookup(ip)
            for asndb in asndbs:
                new_mapping = asndb.lookup(ip) #use pyasn for remaining ips
                if new_mapping[0] != None:
                    found_ips.add(ip)
                    ip_to_asn[ip] = str(new_mapping[0]) #only strings into dict
                    break #finding one mapping is sufficient

    print()
    print("PyASN TRANSLATION")
    print("Not resolved by Cymru: ", len(missing_ips))
    print("Newly found ips: ", len(found_ips))
    print("Fourth, dataset size: ", len(ip_to_asn))

    return ip_to_asn

def resolve_peering_ips(ips, ip_to_asn):
    #
    # THE FOLLOWING PART IS FOR RESOLVING PEERING IPS TO 47065
    #

    peering_prefix = "147.28.224.0/19"
    peering_prefix_2 = "147.28.0.0/16"
    peering_prefix_3 = "45.132.188.0/22"
    peering_prefix_4 = "184.164.255.0/24" #PEERING MUX

    remaining = len(ips)
    missing_ips = set()
    found_ips = set()
    overwritten_ips = set()
    tmp_ips = ips.copy()
    for ip in ips:
        remaining -= 1
        if ip not in ip_to_asn:
            missing_ips.add(ip)
            if ip_in_prefix(ip, peering_prefix) or ip_in_prefix(ip, peering_prefix_2) or ip_in_prefix(ip, peering_prefix_3):
                ip_to_asn[ip] = "47065"
                found_ips.add(ip)
                tmp_ips.remove(ip)
            elif ip_in_prefix(ip, peering_prefix_4):
                ip_to_asn[ip] = "47065-MUX"
                found_ips.add(ip)
                tmp_ips.remove(ip)
        else:
            if ip_in_prefix(ip, peering_prefix) or ip_in_prefix(ip, peering_prefix_2) or ip_in_prefix(ip, peering_prefix_3):
                if ip_to_asn[ip] != "47065": #only count overwritings
                    ip_to_asn[ip] = "47065"
                    overwritten_ips.add(ip)
                    tmp_ips.remove(ip)
            elif ip_in_prefix(ip, peering_prefix_4):
                ip_to_asn[ip] = "47065-MUX"
                found_ips.add(ip)
                tmp_ips.remove(ip)

    print()
    print("PEERING TRANSLATION")
    print("Missing ips from 1: ", len(missing_ips))
    print("Newly found ips: ", len(found_ips))
    print("Overwritten ips: ", len(overwritten_ips))
    print("Second, dataset size: ", len(ip_to_asn))
    print()

    return ip_to_asn, tmp_ips

def determine_missing_ips(ips, ip_to_asn):
    missing_ips = set()
    for ip in ips:
        if ip not in ip_to_asn:
            missing_ips.add(ip)

    print("Finally still missing IPs: ", len(missing_ips))

def resolve_cymru_ips(ips, ip_to_asn, timestamp, date, folder_prefix):
    #write_missing_ips_to_file(ips, timestamp) #necesseray for initial bulk-whois request via DNS
    #cymru_request = "Atlas/pyasn/cymru_"+timestamp+"_request"
    #cymru_response = "Atlas/pyasn/cymru_" + timestamp + "_response"

    cymru_request = folder_prefix + "/" + date + "/" + "cymru_"+timestamp+"_request"
    cymru_response = folder_prefix + "/" + date + "/" + "cymru_" + timestamp + "_response"

    write_cymru_file(ips, cymru_request)
    send_to_cymru(cymru_request, cymru_response)


    missing_ips = set()
    for ip in ips:
        if ip not in ip_to_asn:
            missing_ips.add(ip)

    ip_to_asn, found_ips = read_to_dict_from_cymru_data(cymru_response, ip_to_asn)  # 1. Step - Read from netcat bulk response

    print("CYMRU TRANSLATION")
    print("Missing ips from 1: ", len(missing_ips))
    print("Newly found ips: ", len(found_ips))
    print("Third, dataset size: ", len(ip_to_asn))


    #This is output & saving
    #write_missing_ips_to_file(missing_ips - found_ips)

    return ip_to_asn

def ip_to_binary(ip):
    octet_list_int = ip.split(".")
    octet_list_bin = [format(int(i), '08b') for i in octet_list_int]
    binary = ("").join(octet_list_bin)
    return binary

def get_addr_network(address, net_size):
    #Convert ip address to 32 bit binary
    ip_bin = ip_to_binary(address)
    #Extract Network ID from 32 binary
    network = ip_bin[0:32-(32-net_size)]
    return network

def ip_in_prefix(ip_address, prefix):
    #CIDR based separation of address and network size
    [prefix_address, net_size] = prefix.split("/")
    #Convert string to int
    net_size = int(net_size)
    #Get the network ID of both prefix and ip based net size
    prefix_network = get_addr_network(prefix_address, net_size)
    ip_network = get_addr_network(ip_address, net_size)
    return ip_network == prefix_network

def reached_PEERING(traceroute, folder_prefix, probes_file, pcap_recordings):
    print('Starting Reached_PEERING identification (checking on server-side logs)')
    # "147.28.2.1": ["isi", "anchor"],
    # "147.28.3.1": ["isi", "experiment"],
    # "147.28.4.1": ["gatech", "anchor"],
    # "147.28.5.1": ["gatech", "experiment"],
    #
    # "147.28.8.1": ["seattle_RS", "anchor"],
    # "147.28.9.1": ["seattle_RS", "experiment"],
    # "147.28.10.1": ["seattle_wo_RS", "anchor"],
    # "147.28.11.1": ["seattle_wo_RS", "experiment"],
    #
    # "147.28.12.1": ["amsterdam_RS", "anchor"],
    # "147.28.13.1": ["amsterdam_RS", "experiment"],
    # "147.28.14.1": ["amsterdam_wo_RS", "anchor"],
    # "147.28.15.1": ["amsterdam_wo_RS", "experiment"],
    #
    # "45.132.188.1": ["grnet", "anchor"],
    # "45.132.189.1": ["grnet", "experiment"],
    # "45.132.190.1": ["uw", "anchor"],
    # "45.132.191.1": ["uw", "experiment"],


    #Translate IP paths into ASN paths
    for day in traceroute:
        print()
        print("DAY: ", day)
        for id in traceroute[day]:
            # print(id)
            probe_counter = -1
            measurement = Atlas_rov_identification.read_pickled_measurement_metadata(id, folder_prefix)
            if "seattle_RS" == str(measurement.description).split()[0] and "anchor" in measurement.description:
                target_ip = '147.28.8.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['seattle']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)
            elif "seattle_RS" == str(measurement.description).split()[0] and "experiment" in measurement.description:
                target_ip = '147.28.9.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['seattle']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)
            elif "seattle_wo_RS" == str(measurement.description).split()[0] and "anchor" in measurement.description:
                target_ip = '147.28.10.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['seattle']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)
            elif "seattle_wo_RS" == str(measurement.description).split()[0] and "experiment" in measurement.description:
                target_ip = '147.28.11.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['seattle']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)
            elif "amsterdam_RS" == str(measurement.description).split()[0] and "anchor" in measurement.description:
                target_ip = '147.28.12.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['ams']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)
            elif "amsterdam_RS" == str(measurement.description).split()[0] and "experiment" in measurement.description:
                target_ip = '147.28.13.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['ams']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)
            elif "amsterdam_wo_RS" == str(measurement.description).split()[0] and "anchor" in measurement.description:
                target_ip = '147.28.14.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['ams']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)
            elif "amsterdam_wo_RS" == str(measurement.description).split()[0] and "experiment" in measurement.description:
                target_ip = '147.28.15.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['ams']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)
            elif "gatech" == str(measurement.description).split()[0] and "anchor" in measurement.description:
                target_ip = '147.28.4.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['gatech']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)
            elif "gatech" == str(measurement.description).split()[0] and "experiment" in measurement.description:
                target_ip = '147.28.5.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['gatech']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)
            elif "isi" == str(measurement.description).split()[0] and "anchor" in measurement.description:
                target_ip = '147.28.2.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['isi']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)
            elif "isi" == str(measurement.description).split()[0] and "experiment" in measurement.description:
                target_ip = '147.28.3.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['isi']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)
            elif "grnet" == str(measurement.description).split()[0] and "anchor" in measurement.description:
                target_ip = '45.132.188.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['grnet']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)
            elif "grnet" == str(measurement.description).split()[0] and "experiment" in measurement.description:
                target_ip = '45.132.189.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['grnet']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)
            elif "uw" == str(measurement.description).split()[0] and "anchor" in measurement.description:
                target_ip = '45.132.190.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['uw']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)
            elif "uw" == str(measurement.description).split()[0] and "experiment" in measurement.description:
                target_ip = '45.132.191.1'
                ips_that_reached_peering = set()
                for packet in pcap_recordings[day]['uw']:
                    if packet[IP].dst == target_ip:
                        ips_that_reached_peering.add(packet[IP].src)

            else:
                print()
                print('ERROR - No pcap could be found that mapped the PEERING PoP!')
                print()

            for probe in traceroute[day][id]:
                probe = reached_PEERING_per_trace(probe, probes_file, ips_that_reached_peering, target_ip)
    print('Finished Reached_PEERING identification (checking on server-side logs)')
    return traceroute



def reached_PEERING_per_trace(probe, probes_file, ips_that_reached_peering, target_ip):
    probe['reached_PEERING'] = False
    peering_mux = '184.164.255.0/24'
    if probe['asn_path'][-1] == "47065": #probe claims to have reached PEERING
        #those two should be the same but most probes sit behind a NAT, therefore we check the public IP from the meta data
        src_addr = probe['src_addr']
        public_ip = find_probes_public_ip(probes_file, probe['prb_id'])
        if src_addr in ips_that_reached_peering or public_ip in ips_that_reached_peering:
            probe['reached_PEERING'] = True
        else:
            counter_found = set()
            counter_not_found = set()
            probe_id = probe['prb_id']
            try:
                if probe['result'][-1:][0]['result'][0]['from'] == target_ip:
                    try:
                        if ip_in_prefix(probe['result'][-2:][0]['result'][0]['from'], peering_mux) == True:
                            counter_found.add(probe_id)
                            probe['reached_PEERING'] = True
                        else:
                            # print(successful_probes_data[probe_id]['result'])
                            counter_not_found.add(probe_id)
                    except:
                        try:
                            if ip_in_prefix(probe['result'][-2:][0]['result'][1]['from'], peering_mux) == True:
                                counter_found.add(probe_id)
                                probe['reached_PEERING'] = True
                            else:
                                # print(successful_probes_data[probe_id]['result'])
                                counter_not_found.add(probe_id)
                        except:
                            try:
                                if ip_in_prefix(probe['result'][-2:][0]['result'][2]['from'], peering_mux) == True:
                                    counter_found.add(probe_id)
                                    probe['reached_PEERING'] = True
                                else:
                                    # print(successful_probes_data[probe_id]['result'])
                                    counter_not_found.add(probe_id)
                            except:
                                counter_not_found.add(probe_id)
                                # print(successful_probes_data[probe_id]['result'][-1:][0]['result'][0])
                                # print(successful_probes_data[probe_id]['result'][-2:][0]['result'][0])
                                # print(successful_probes_data[probe_id]['result'][-2:][0]['result'][1])
                                # print(successful_probes_data[probe_id]['result'][-2:][0]['result'][2])
            except:
                try:
                    if probe['result'][-1:][0]['result'][1]['from'] == target_ip:
                        try:
                            if ip_in_prefix(probe['result'][-2:][0]['result'][0]['from'], peering_mux) == True:
                                counter_found.add(probe_id)
                                probe['reached_PEERING'] = True
                            else:
                                # print(successful_probes_data[probe_id]['result'])
                                counter_not_found.add(probe_id)
                        except:
                            try:
                                if ip_in_prefix(probe['result'][-2:][0]['result'][1]['from'], peering_mux) == True:
                                    counter_found.add(probe_id)
                                    probe['reached_PEERING'] = True
                                else:
                                    # print(successful_probes_data[probe_id]['result'])
                                    counter_not_found.add(probe_id)
                            except:
                                try:
                                    if ip_in_prefix(probe['result'][-2:][0]['result'][2]['from'], peering_mux) == True:
                                        counter_found.add(probe_id)
                                        probe['reached_PEERING'] = True
                                    else:
                                        # print(successful_probes_data[probe_id]['result'])
                                        counter_not_found.add(probe_id)
                                except:
                                    counter_not_found.add(probe_id)
                                    print(probe['result'][-1:][0]['result'][0])
                                    print(probe['result'][-2:][0]['result'][0])
                                    print(probe['result'][-2:][0]['result'][1])
                                    print(probe['result'][-2:][0]['result'][2])
                except:
                    try:
                        if probe['result'][-1:][0]['result'][1]['from'] == target_ip:
                            try:
                                if ip_in_prefix(probe['result'][-2:][0]['result'][0]['from'], peering_mux) == True:
                                    counter_found.add(probe_id)
                                    probe['reached_PEERING'] = True
                                else:
                                    # print(successful_probes_data[probe_id]['result'])
                                    counter_not_found.add(probe_id)
                            except:
                                try:
                                    if ip_in_prefix(probe['result'][-2:][0]['result'][1]['from'], peering_mux) == True:
                                        counter_found.add(probe_id)
                                        probe['reached_PEERING'] = True
                                    else:
                                        # print(successful_probes_data[probe_id]['result'])
                                        counter_not_found.add(probe_id)
                                except:
                                    try:
                                        if ip_in_prefix(probe['result'][-2:][0]['result'][2]['from'], peering_mux) == True:
                                            counter_found.add(probe_id)
                                            probe['reached_PEERING'] = True
                                        else:
                                            # print(successful_probes_data[probe_id]['result'])
                                            counter_not_found.add(probe_id)
                                    except:
                                        counter_not_found.add(probe_id)
                                        print(probe['result'][-1:][0]['result'][0])
                                        print(probe['result'][-2:][0]['result'][0])
                                        print(probe['result'][-2:][0]['result'][1])
                                        print(probe['result'][-2:][0]['result'][2])
                    except:
                        print('Except!')
                        print()
                        print(probe)
    return probe


def find_probes_public_ip(probes_file, probe_id):
    for probe in probes_file['objects']:
        if probe['id'] == probe_id:
            return probe['address_v4']
    return False

def translate_ip_to_asn_paths(traceroute, ip_to_asn, probes_to_asn):
    print('Starting IP->ASN Translation')

    #Translate IP paths into ASN paths
    for day in traceroute:
        print()
        print("DAY: ", day)
        for id in traceroute[day]:
            # print(id)
            probe_counter = -1
            for probe in traceroute[day][id]:
                probe = translate_per_trace(probe, probes_to_asn, ip_to_asn, True)

    print('Finished IP->ASN Translation')
    return traceroute

def translate_per_trace(probe, probes_to_asn, ip_to_asn, shortening=True):

    asn_path = []
    PEERING_success = False

    # Add probe ASN here
    probe_asn = probes_to_asn[probe['prb_id']]
    asn_path.append(str(probe_asn))

    #probe_counter += 1
    hop_counter = 0
    for hop in probe['result']:
        hop_counter += 1
        asn_path.append("*")
        try:  # sometimes result looks like: {'error': 'name resolution failed: non-recoverable failure in name resolution (1)'}
            initial_iteration = ""
            for result in hop["result"]:
                try:  # Sometimes there is no from but instead on "x: *"
                    if initial_iteration == "":
                        initial_iteration = result["from"]
                        asn = ip_to_asn[initial_iteration]  # this needs to be before pop() such when it fails, we don´t remove the *
                        asn_path.pop()
                        asn_path.append(asn)
                except:
                    pass
        except:
            pass
    # print()
    # print("Day " + str(day) + ", id: " + str(id) + ", probe_nr: " + str(probe_counter))
    # for k,v in asn_path.items():
    #    print(str(k) + " " + str(v))

    # Save in json if second last hop was the MUX responding with * and the last hop was PEERING control-server
    probe['reached_PEERING'] = False
    if asn_path[-1] == "47065" and (asn_path[-2] == "*" or asn_path[-2] == "47065-MUX"): probe['reached_PEERING'] = True
    if asn_path.count('47065') > 1: probe['reached_PEERING'] = False  # This is to avoid sth like the follwing being valid: ['33588', 'private', '*', '47065', '47065', '47065', '47065', '47065', '47065', '47065', '47065', '47065', '*', '47065']

    if shortening == True: asn_path = shorten_path(asn_path)
    probe['asn_path'] = asn_path

    return probe

def remove_neighboring_asns(tmp_asn_path):

    for index in range(len(tmp_asn_path)):
        if index+1 < len(tmp_asn_path):
            if tmp_asn_path[index] != "*" and tmp_asn_path[index] == tmp_asn_path[index+1]:
                print("Removing: ", tmp_asn_path[index+1])
                del tmp_asn_path[index+1]
                tmp_asn_path = remove_neighboring_asns(tmp_asn_path)
                break

    return tmp_asn_path

def remove_private_ASNs(asn_path):
    tmp_asn_path = []
    for asn in asn_path:
        if asn != "private":
            tmp_asn_path.append(asn)
    return tmp_asn_path

def replace_private_ASNs(asn_path):
    tmp_asn_path = []
    for asn in asn_path:
        if asn != "private":
            tmp_asn_path.append(asn)
        else:
            tmp_asn_path.append('*')
    return tmp_asn_path

def remove_consecutive_duplicates(asn_path):
    tmp_asn_path = []
    for asn in asn_path:
        if tmp_asn_path[-1:] == []:
            tmp_asn_path.append(asn)
        elif asn != tmp_asn_path[-1] or asn == "*": # Remove same ASes in a row but leave *
            tmp_asn_path.append(asn)
    return tmp_asn_path

def remove_intermediate_unresponsive_ases(asn_path):

    #This recursive function removes intemediate "*" symbols between two ASNs of the same type
    for index in range(len(asn_path)):
        #print(index+2, len(asn_path)-2)
        for i in range (index+2, len(asn_path)):
            #print(i)
            if asn_path[index] != "*" and i < len(asn_path):
                if asn_path[index] == asn_path[i] and asn_path[i-1] == "*":
                    del asn_path[i-1]
                    asn_path = remove_intermediate_unresponsive_ases(asn_path)
                    break
    return asn_path

def shorten_path(asn_path):
    # Remove second last hop when TR was successful (MUX doesn´t respond or responds with IP from 184.164.255/24 range)
    if asn_path[-1] == "47065" and (asn_path[-2] == "*" or asn_path[-2] == "47065-MUX"):
        del asn_path[len(asn_path)-2]

    # Transform 'private' into '*' as for our logic it does not make a difference if the answer was not provided or provided by a private IP. We don´t know the AS it came from.
    asn_path = replace_private_ASNs(asn_path)

    for i in range(1): #Repeat three times just to be sure to have shortened everything properly
        # Remove * inbetween same ASes
        asn_path = remove_intermediate_unresponsive_ases(asn_path)

        # Remove same ASes in a row but leave *
        asn_path = remove_consecutive_duplicates(asn_path)

    #print(asn_path)

    return asn_path

def load_probes_info(probes_info):
    probes_to_asn = {}
    with open(probes_info, "r") as read_file:
        file = json.load(read_file)
        for probe in file['objects']:
            probes_to_asn[probe['id']] = probe['asn_v4']
    print('Done reading probes file')
    return probes_to_asn

def save_asn_path_to_updated_file(measurement_ids, traceroute, folder_prefix, date, previous_day):

    print()
    print("Started saving updated files")

    #previous day
    for traceroute_measurement in measurement_ids[0]['traceroute']:
        with open(folder_prefix+"/"+ previous_day + "/traceroute/" + str(traceroute_measurement)+"_updated.json", "w") as write_file:
            traceroute[0][traceroute_measurement] = json.dump(traceroute[0][traceroute_measurement], write_file)

    #actual day
    for traceroute_measurement in measurement_ids[1]['traceroute']:
        with open(folder_prefix+"/"+ date + "/traceroute/" + str(traceroute_measurement)+"_updated.json", "w") as write_file:
            traceroute[1][traceroute_measurement] = json.dump(traceroute[1][traceroute_measurement], write_file)

    print("Finished saving updated files")

def main(args):



if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
