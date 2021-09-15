__author__ = "Nils Rodday"
__copyright__ = "Copyright 2019"
__credits__ = ["Nils Rodday"]
__email__ = "nils.rodday@unibw.de"
__status__ = "Experimental"

# Get input list from https://ftp.ripe.net/ripe/atlas/probes/archive/2019/10/
import itertools
import sys, os
import argparse
import copy
import json
import math
from ipwhois import IPWhois
from calendar import timegm
import csv
import pandas as pd
import subprocess
import shlex
import pyasn
import networkx as nx
import pygraphviz
import matplotlib
# matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from sklearn.cluster import KMeans
from sklearn.cluster import OPTICS
from sklearn import metrics
from scipy.spatial.distance import cdist
import os.path
import pickle
import urllib.request
from bs4 import BeautifulSoup

import time as normal_time
from datetime import datetime, date, time, timedelta
from ripe.atlas.cousteau import AtlasResultsRequest, Measurement, Probe
from ripe.atlas.sagan import HttpResult, TracerouteResult

import ip_to_asn
from traixroute.application import run_traixroute

import glob

from scapy.all import *

# Disable
def blockPrint():
    sys.stdout = open(os.devnull, 'w')

# Restore
def enablePrint():
    sys.stdout = sys.__stdout__

def parse_arguments(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("ip_to_asn_file", help="IP to ASN mapping file (Cache)")
    return parser.parse_args(args)


def read_cache_file(ip_to_asn_file):
    with open(ip_to_asn_file, "r") as read_file:
        file = json.load(read_file)
    return file


def load_ids(traceroute_ids, http_ids):
    measurement_ids = {}

    measurement_ids[0] = {}
    measurement_ids[0]['http'] = http_ids[0]
    measurement_ids[0]['traceroute'] = traceroute_ids[0]

    measurement_ids[1] = {}
    measurement_ids[1]['http'] = http_ids[1]
    measurement_ids[1]['traceroute'] = traceroute_ids[1]

    # measurement_ids[day]["http"|"traceroute"] = [numbers]
    return measurement_ids


def load_measurements(measurement_ids, folder_prefix, date, previous_day):

    print(measurement_ids)
    http = {}
    traceroute = {}

    http[0] = {}
    traceroute[0] = {}
    http[1] = {}
    traceroute[1] = {}

    for http_measurement in measurement_ids[0]['http']:
       with open(folder_prefix + "/" + previous_day + "/http/" + str(http_measurement) + ".json","r") as read_file:
            http[0][http_measurement] = json.load(read_file)

    for traceroute_measurement in measurement_ids[0]['traceroute']:
        with open(folder_prefix + "/" + previous_day + "/traceroute/" + str(traceroute_measurement) + ".json","r") as read_file:
            traceroute[0][traceroute_measurement] = json.load(read_file)

    for http_measurement in measurement_ids[1]['http']:
       with open(folder_prefix + "/" + date + "/http/" + str(http_measurement) + ".json","r") as read_file:
            http[1][http_measurement] = json.load(read_file)

    for traceroute_measurement in measurement_ids[1]['traceroute']:
        with open(folder_prefix + "/" + date + "/traceroute/" + str(traceroute_measurement) + ".json","r") as read_file:
            traceroute[1][traceroute_measurement] = json.load(read_file)

    return http, traceroute


def load_updated_measurements(measurement_ids, folder_prefix, date, previous_day):

    #print(measurement_ids)
    http = {}
    traceroute = {}

    http[0] = {}
    traceroute[0] = {}
    http[1] = {}
    traceroute[1] = {}

    for http_measurement in measurement_ids[0]['http']:
       with open(folder_prefix + "/" + previous_day + "/http/" + str(http_measurement) + ".json","r") as read_file:
            http[0][http_measurement] = json.load(read_file)

    for traceroute_measurement in measurement_ids[0]['traceroute']:
        with open(folder_prefix + "/" + previous_day + "/traceroute/" + str(traceroute_measurement) + "_updated.json","r") as read_file:
            traceroute[0][traceroute_measurement] = json.load(read_file)

    for http_measurement in measurement_ids[1]['http']:
       with open(folder_prefix + "/" + date + "/http/" + str(http_measurement) + ".json","r") as read_file:
            http[1][http_measurement] = json.load(read_file)

    for traceroute_measurement in measurement_ids[1]['traceroute']:
        with open(folder_prefix + "/" + date + "/traceroute/" + str(traceroute_measurement) + "_updated.json","r") as read_file:
            traceroute[1][traceroute_measurement] = json.load(read_file)

    return http, traceroute


def load_probes_info(probes_info):
    probes_to_asn = {}
    with open(probes_info, "r") as read_file:
        file = json.load(read_file)
        for probe in file['objects']:
            probes_to_asn[probe['id']] = probe['asn_v4']
    print('Done reading probes file')
    return probes_to_asn

def download_PEERING_peer_list(path):


    NonAsciiCharDict = {
        '✔': True,
        '✘': False,
        '—': None,
    }

    url = "https://peering.ee.columbia.edu/peers/"

    print('Starting PEERING peer list download.')
    with urllib.request.urlopen(url) as rsp:
        html = rsp.read()

        page = BeautifulSoup(html, features="html.parser")

        peers_table = page.find("table")
        peers_rows = peers_table.tbody.find_all("tr")
        peers_attrs = [cell.text.strip() for cell in peers_table.thead.find_all("th")]

        result = []
        for r in peers_rows:
            cells = r.find_all("td")
            entry = {}
            for idx, cell in enumerate(cells):
                value = cell.text.strip()
                if value in NonAsciiCharDict:
                    value = NonAsciiCharDict[value]

                if idx < len(peers_attrs):
                    entry[peers_attrs[idx]] = value

            result.append(entry)

        with open(path, 'w') as f:
            json.dump(result, f, indent=2)

        print('Finished PEERING peer list download.')

# This function downloads the PEERING peer list and returns True if the asn is in it, otherwise False
def is_direct_PEERING_peer(asn, folder_prefix, date):
    path = folder_prefix + "/" + date + "/PEERING_peers.json"
    if not os.path.exists(path): #Download only if necessary
        download_PEERING_peer_list(path)

    with open(path, "r") as read_file:
        peering_peers = json.load(read_file)
        for peer in peering_peers:
            if str(peer["Peer ASN"]) == asn:
                return True

    return False

#measurements is: traceroute[day], pop is e.g. "neu", validity is "anchor" or "experiment"
def find_matching_measurement(measurements, pop, validity, folder_prefix):
    for id in measurements:
        measurement = read_pickled_measurement_metadata(id, folder_prefix)
        new_pop = str(measurement.description).split()[0]
        if new_pop == pop and validity in measurement.description:
            return id
    return False #Could not find a matching measurement

def show_ixp_crossings(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2):
    # Show IXP Crossings, if present
    if probe["ixp_crossings"] != None:
        return probe["ixp_crossings"]
    elif probe_2["ixp_crossings"] != None:
        return probe_2["ixp_crossings"]
    elif previous_day_probe_anchor["ixp_crossings"] != None:
        return previous_day_probe_anchor["ixp_crossings"]
    elif previous_day_probe_experiment["ixp_crossings"] != None:
        return previous_day_probe_experiment["ixp_crossings"]
    return False #Default to False
    #print("IXP CROSSING DETECTED")
    #print(probe, probe_2, previous_day_probe_anchor, previous_day_probe_experiment)
    #print()

def extract_all_traces(traceroute, folder_prefix, date):
    print("**********")
    print("**********")
    print("Extracting traces")
    print("**********")
    print("**********")

    all_traces = []

    previous_day = 0
    day=1 #Only for one day in ongoing measurements
    all_good_length_2 = {} #whitelist 1hop
    all_good_length_2[day] = {}
    potentially_filtering_asns_invalid_died_length_2 = {} #case 2a
    potentially_filtering_asns_invalid_died_length_2[day] = {}
    potentially_filtering_asns_invalid_diverged_length_2 = {} #case 2b
    potentially_filtering_asns_invalid_diverged_length_2[day] = {}

    all_good_length_more_than_2 = {}
    all_good_length_more_than_2[day] = {}
    potentially_filtering_asns_invalid_died_length_more_than_2 = {}
    potentially_filtering_asns_invalid_died_length_more_than_2[day] = {}
    potentially_filtering_asns_path_diversion_length_more_than_2 = {}
    potentially_filtering_asns_path_diversion_length_more_than_2[day] = {}

    for id in traceroute[day]:
        measurement = read_pickled_measurement_metadata(id, folder_prefix)

        if "experiment" in measurement.description: continue
        print(id, measurement.description)
        pop = measurement.description.split()[0]
        print()
        print("ID " + str(id) + " - " + str(measurement.description))
        probe_counter = -1
        occurences = 0

        for probe in traceroute[day][id]:
            probe_counter += 1
            # print(probe["asn_path"])

            probe_2_counter = -1
            invalid_id = find_matching_measurement(traceroute[day], pop, "experiment", folder_prefix)

            #invalid_measurement = read_pickled_measurement_metadata(invalid_id, folder_prefix)
            #print("day1 - Valid  : ", id, measurement.description)
            #print("day1 - Invalid: ",invalid_id, invalid_measurement.description)
            for probe_2 in traceroute[day][invalid_id]:  # Search for match in invalid set
                probe_2_counter += 1
                if probe['prb_id'] == probe_2['prb_id']:

                    #Search for both same as valid path during previous day (valid day for experiment prefix)
                    for previous_day_id in traceroute[0]:
                        previous_day_measurement = read_pickled_measurement_metadata(previous_day_id, folder_prefix)
                        if pop != previous_day_measurement.description.split()[0]: continue #loook for the same pop
                        if "experiment" in previous_day_measurement.description: continue #Look for anchor

                        previous_day_probe_anchor_counter = -1
                        for previous_day_probe_anchor in traceroute[0][previous_day_id]:  # Search for match for anchor on previous day
                            previous_day_probe_anchor_counter += 1
                            if probe['prb_id'] == previous_day_probe_anchor['prb_id']:
                                previous_day_invalid_id = find_matching_measurement(traceroute[0], pop, "experiment",folder_prefix)
                                #previous_day_invalid_measurement = read_pickled_measurement_metadata(previous_day_invalid_id,folder_prefix)
                                #print("day0 - Valid  : ", previous_day_id, previous_day_measurement.description)
                                #print("day0 - Invalid: ", previous_day_invalid_id, previous_day_invalid_measurement.description)

                                previous_day_probe_experiment_counter = -1
                                for previous_day_probe_experiment in traceroute[0][previous_day_invalid_id]:  # Search for match in invalid set of previous day
                                    previous_day_probe_experiment_counter += 1
                                    if previous_day_probe_anchor['prb_id'] == previous_day_probe_experiment['prb_id']:

                                        identification_label = "Day 0 --- ID valid: " + str(
                                            previous_day_id) + ", ProbeValidLocation: " + str(
                                            previous_day_probe_anchor_counter) + ", ID invalid: " + str(
                                            previous_day_invalid_id) + ", ProbeInvalidLocation: " + str(
                                            previous_day_probe_experiment_counter) + " : Day 1 --- ID valid: " + str(
                                            id) + ", ProbeValidLocation: " + str(
                                            probe_counter) + ", ID invalid: " + str(
                                            invalid_id) + ", ProbeInvalidLocation: " + str(probe_2_counter)

                                        ixp_info = show_ixp_crossings(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2)

                                        all_traces.append((previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, id, day, identification_label, ixp_info, pop))
    print('Done rendering all traces')
    return all_traces


#this can be probably be removed
def start_eval(all_traces, traceroute, folder_prefix, all_good_length_2, potentially_filtering_asns_invalid_died_length_2, potentially_filtering_asns_invalid_diverged_length_2, all_good_length_more_than_2, potentially_filtering_asns_invalid_died_length_more_than_2, potentially_filtering_asns_path_diversion_length_more_than_2):
    # show_ixp_crossings(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2)


    if id not in all_good_length_2[day]:
        all_good_length_2[day][id] = {}
    if id not in potentially_filtering_asns_invalid_died_length_2[day]:
        potentially_filtering_asns_invalid_died_length_2[day][id] = {}
    if id not in potentially_filtering_asns_invalid_diverged_length_2[day]:
        potentially_filtering_asns_invalid_diverged_length_2[day][id] = {}

    if id not in all_good_length_more_than_2[day]:
        all_good_length_more_than_2[day][id] = {}
    if id not in potentially_filtering_asns_invalid_died_length_more_than_2[day]:
        potentially_filtering_asns_invalid_died_length_more_than_2[day][id] = {}
    if id not in potentially_filtering_asns_path_diversion_length_more_than_2[day]:
        potentially_filtering_asns_path_diversion_length_more_than_2[day][id] = {}

    successful_1_hop_asn = perform_whitelist_1hop(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2) #returns single asn
    if successful_1_hop_asn != None:
        all_good_length_2 = save_result(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, successful_1_hop_asn, day, id, ixp_info, identification_label, all_good_length_2)


    case2a_asn = perform_traceroute_eval_case_2a_new(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2)
    if case2a_asn != None:
        potentially_filtering_asns_invalid_died_length_2 = save_result(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, case2a_asn, day, id, ixp_info, identification_label, potentially_filtering_asns_invalid_died_length_2)

    #pickle.dump(case2a, open(folder_prefix + "/" + date + "/case2a.pickle", "wb"))
    #pickle.dump(successful_1_hop, open(folder_prefix + "/" + date + "/successful_1_hop.pickle", "wb"))

    case2b_asn = perform_traceroute_eval_case_2b_new(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2)
    if case2b_asn != None:
        potentially_filtering_asns_invalid_diverged_length_2 = save_result(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, case2b_asn, day, id, ixp_info, identification_label, potentially_filtering_asns_invalid_diverged_length_2)


    # pickle.dump(case2b, open(folder_prefix + "/" + date + "/case2b.pickle", "wb"))


    successful_2plus_hop = perform_whitelist_2hop(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2) #returns list
    if successful_2plus_hop != None:
        for asn in successful_2plus_hop:
            all_good_length_more_than_2 = save_result(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, asn, day, id, ixp_info, identification_label, all_good_length_more_than_2)


    case4a_asn = perform_traceroute_eval_case_4a_new(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, traceroute, pop, day, id, potentially_filtering_asns_invalid_died_length_2,potentially_filtering_asns_invalid_diverged_length_2, folder_prefix)
    if case4a_asn != None:
        potentially_filtering_asns_invalid_died_length_more_than_2 = save_result(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, case4a_asn, day, id, ixp_info, identification_label, potentially_filtering_asns_invalid_died_length_more_than_2)


    #print('Return value: ', case2b_asn)
    # pickle.dump(case4a, open(folder_prefix + "/" + date + "/case4a.pickle", "wb"))
    # pickle.dump(successful_2plus_hop, open(folder_prefix + "/" + date + "/successful_2plus_hop.pickle", "wb"))

    case4b_asn = perform_traceroute_eval_case_4b_new(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, traceroute, pop, day, id, potentially_filtering_asns_invalid_died_length_2, potentially_filtering_asns_invalid_diverged_length_2, potentially_filtering_asns_invalid_died_length_more_than_2, folder_prefix)
    if case4b_asn != None:
        potentially_filtering_asns_path_diversion_length_more_than_2 = save_result(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, case4b_asn, day, id, ixp_info, identification_label, potentially_filtering_asns_path_diversion_length_more_than_2)


    # pickle.dump(case4b, open(folder_prefix + "/" + date + "/case4b.pickle", "wb"))


    if (successful_1_hop_asn != None or
        case2a_asn != None or
        case2b_asn != None or
        successful_2plus_hop != None or
        case4a_asn != None or
        case4b_asn != None):


            print()
            print(identification_label)

            print("Day 0 Anchor      ", previous_day_probe_anchor["asn_path"])
            print("Day 0 Experiment  ", previous_day_probe_experiment["asn_path"])
            print("Day 1 Anchor      ", probe["asn_path"])
            print("Day 1 Experiment  ", probe_2["asn_path"])
            print('whitelisted: ', successful_1_hop_asn)
            print('Case2a: ', case2a_asn)
            print('Case2b: ', case2b_asn)
            print('whitelisted: ', successful_2plus_hop)
            print('Case4a: ', case4a_asn)
            print('Case4b: ', case4b_asn)


def eval_whitelist_1hop(all_traces):
    # all_traces == ((previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, id, day, identification_label, ixp_info, pop))

    day = all_traces[0][5] #pick first item and take day
    all_good_length_2 = {} #whitelist 1hop
    all_good_length_2[day] = {}

    for trace in all_traces:
        id = trace[4]
        if id not in all_good_length_2[day]:
            all_good_length_2[day][id] = {}

        result_asn = perform_whitelist_1hop_new(trace[0], trace[1], trace[2], trace[3])
        if result_asn != None:
            all_good_length_2 = save_result(trace[0], trace[1], trace[2], trace[3], result_asn, trace[5], trace[4], trace[7], trace[6], all_good_length_2)

            print(trace[6])
            print("Day 0 Anchor      ", trace[0]["asn_path"])
            print("Day 0 Experiment  ", trace[1]["asn_path"])
            print("Day 1 Anchor      ", trace[2]["asn_path"])
            print("Day 1 Experiment  ", trace[3]["asn_path"])
            print('Whitelist 1hop ASN: ', result_asn)

    return all_good_length_2

def eval_case_2a(all_traces):
    # all_traces == ((previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, id, day, identification_label, ixp_info, pop))

    day = all_traces[0][5] #pick first item and take day
    all_good_length_2 = {} #whitelist 1hop
    all_good_length_2[day] = {}
    potentially_filtering_asns_invalid_died_length_2 = {} #case 2a
    potentially_filtering_asns_invalid_died_length_2[day] = {}
    potentially_filtering_asns_invalid_diverged_length_2 = {} #case 2b
    potentially_filtering_asns_invalid_diverged_length_2[day] = {}

    all_good_length_more_than_2 = {}
    all_good_length_more_than_2[day] = {}
    potentially_filtering_asns_invalid_died_length_more_than_2 = {}
    potentially_filtering_asns_invalid_died_length_more_than_2[day] = {}
    potentially_filtering_asns_path_diversion_length_more_than_2 = {}
    potentially_filtering_asns_path_diversion_length_more_than_2[day] = {}

    for trace in all_traces:
        id = trace[4]
        if id not in potentially_filtering_asns_invalid_died_length_2[day]:
            potentially_filtering_asns_invalid_died_length_2[day][id] = {}

        result_asn = perform_traceroute_eval_case_2a_new(trace[0], trace[1], trace[2], trace[3])
        if result_asn != None:
            potentially_filtering_asns_invalid_died_length_2 = save_result(trace[0], trace[1], trace[2], trace[3], result_asn, trace[5], trace[4], trace[7], trace[6], potentially_filtering_asns_invalid_died_length_2)

            print(trace[6])
            print("Day 0 Anchor      ", trace[0]["asn_path"])
            print("Day 0 Experiment  ", trace[1]["asn_path"])
            print("Day 1 Anchor      ", trace[2]["asn_path"])
            print("Day 1 Experiment  ", trace[3]["asn_path"])
            print('Case2a: ', result_asn)

    return potentially_filtering_asns_invalid_died_length_2

def eval_case_2b(all_traces):
    # all_traces == ((previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, id, day, identification_label, ixp_info, pop))

    day = all_traces[0][5] #pick first item and take day
    all_good_length_2 = {} #whitelist 1hop
    all_good_length_2[day] = {}
    potentially_filtering_asns_invalid_died_length_2 = {} #case 2a
    potentially_filtering_asns_invalid_died_length_2[day] = {}
    potentially_filtering_asns_invalid_diverged_length_2 = {} #case 2b
    potentially_filtering_asns_invalid_diverged_length_2[day] = {}

    all_good_length_more_than_2 = {}
    all_good_length_more_than_2[day] = {}
    potentially_filtering_asns_invalid_died_length_more_than_2 = {}
    potentially_filtering_asns_invalid_died_length_more_than_2[day] = {}
    potentially_filtering_asns_path_diversion_length_more_than_2 = {}
    potentially_filtering_asns_path_diversion_length_more_than_2[day] = {}

    for trace in all_traces:
        id = trace[4]
        if id not in potentially_filtering_asns_invalid_diverged_length_2[day]:
            potentially_filtering_asns_invalid_diverged_length_2[day][id] = {}

        result_asn = perform_traceroute_eval_case_2b_new(trace[0], trace[1], trace[2], trace[3])
        if result_asn != None:
            potentially_filtering_asns_invalid_diverged_length_2 = save_result(trace[0], trace[1], trace[2], trace[3], result_asn, trace[5], trace[4], trace[7], trace[6], potentially_filtering_asns_invalid_diverged_length_2)

            print(trace[6])
            print("Day 0 Anchor      ", trace[0]["asn_path"])
            print("Day 0 Experiment  ", trace[1]["asn_path"])
            print("Day 1 Anchor      ", trace[2]["asn_path"])
            print("Day 1 Experiment  ", trace[3]["asn_path"])
            print('Case2b: ', result_asn)

    return potentially_filtering_asns_invalid_diverged_length_2

def eval_whitelist_2hops(all_traces):
    # all_traces == ((previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, id, day, identification_label, ixp_info, pop))

    day = all_traces[0][5] #pick first item and take day
    all_good_length_more_than_2 = {} #whitelist 2hop
    all_good_length_more_than_2[day] = {}

    for trace in all_traces:
        id = trace[4]
        if id not in all_good_length_more_than_2[day]:
            all_good_length_more_than_2[day][id] = {}

        result_asns = perform_whitelist_2hops_new(trace[0], trace[1], trace[2], trace[3])
        if result_asns != None:
            for result_asn in result_asns:
                if result_asn != '*':
                    all_good_length_more_than_2 = save_result(trace[0], trace[1], trace[2], trace[3], result_asn, trace[5], trace[4], trace[7], trace[6], all_good_length_more_than_2)

            print(trace[6])
            print("Day 0 Anchor      ", trace[0]["asn_path"])
            print("Day 0 Experiment  ", trace[1]["asn_path"])
            print("Day 1 Anchor      ", trace[2]["asn_path"])
            print("Day 1 Experiment  ", trace[3]["asn_path"])
            print('Whitelist 2hop ASNs (w/o *): ', result_asns)

    return all_good_length_more_than_2

def eval_case_4a(all_traces, traceroute, case2a, case2b, folder_prefix):
    # all_traces == ((previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, id, day, identification_label, ixp_info, pop))

    day = all_traces[0][5] #pick first item and take day
    potentially_filtering_asns_invalid_died_length_more_than_2 = {}
    potentially_filtering_asns_invalid_died_length_more_than_2[day] = {}

    for trace in all_traces:
        id = trace[4]
        if id not in potentially_filtering_asns_invalid_died_length_more_than_2[day]:
            potentially_filtering_asns_invalid_died_length_more_than_2[day][id] = {}

        result_asn = perform_traceroute_eval_case_4a_new(trace[0], trace[1], trace[2], trace[3], traceroute, trace[8], trace[5], trace[4], case2a, case2b, folder_prefix)
        #previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, traceroute, pop, day, id, potentially_filtering_asns_invalid_died_length_2, potentially_filtering_asns_invalid_diverged_length_2, folder_prefix
        if result_asn != None:
            potentially_filtering_asns_invalid_died_length_more_than_2 = save_result(trace[0], trace[1], trace[2], trace[3], result_asn, trace[5], trace[4], trace[7], trace[6], potentially_filtering_asns_invalid_died_length_more_than_2)

            print(trace[6])
            print("Day 0 Anchor      ", trace[0]["asn_path"])
            print("Day 0 Experiment  ", trace[1]["asn_path"])
            print("Day 1 Anchor      ", trace[2]["asn_path"])
            print("Day 1 Experiment  ", trace[3]["asn_path"])
            print('Case4a: ', result_asn)

    return potentially_filtering_asns_invalid_died_length_more_than_2

def eval_case_4b(all_traces, traceroute, case2a, case2b, case4a, folder_prefix):
    # all_traces == ((previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, id, day, identification_label, ixp_info, pop))

    day = all_traces[0][5] #pick first item and take day
    potentially_filtering_asns_path_diversion_length_more_than_2 = {}
    potentially_filtering_asns_path_diversion_length_more_than_2[day] = {}

    for trace in all_traces:
        id = trace[4]
        if id not in potentially_filtering_asns_path_diversion_length_more_than_2[day]:
            potentially_filtering_asns_path_diversion_length_more_than_2[day][id] = {}

        result_asn = perform_traceroute_eval_case_4b_new(trace[0], trace[1], trace[2], trace[3], traceroute, trace[8], trace[5], trace[4], case2a, case2b, case4a, folder_prefix)
        #previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, traceroute, pop, day, id, potentially_filtering_asns_invalid_died_length_2, potentially_filtering_asns_invalid_diverged_length_2, folder_prefix
        if result_asn != None:
            potentially_filtering_asns_path_diversion_length_more_than_2 = save_result(trace[0], trace[1], trace[2], trace[3], result_asn, trace[5], trace[4], trace[7], trace[6], potentially_filtering_asns_path_diversion_length_more_than_2)

            print(trace[6])
            print("Day 0 Anchor      ", trace[0]["asn_path"])
            print("Day 0 Experiment  ", trace[1]["asn_path"])
            print("Day 1 Anchor      ", trace[2]["asn_path"])
            print("Day 1 Experiment  ", trace[3]["asn_path"])
            print('Case4b: ', result_asn)

    return potentially_filtering_asns_path_diversion_length_more_than_2


def save_result(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, asn, day, id, ixp_info, identification_label, a):
    if asn not in a[day][id]:
        a[day][id][asn] = []

    if ixp_info == False:
        # if (previous_day_probe_anchor["asn_path"],previous_day_probe_experiment["asn_path"],probe["asn_path"], probe_2["asn_path"],'noIXP',identification_label) not in potentially_filtering_asns_invalid_died_length_2[day][id][asn]:
        a[day][id][asn].append((previous_day_probe_anchor["asn_path"], previous_day_probe_experiment["asn_path"], probe["asn_path"], probe_2["asn_path"], 'noIXP', identification_label))
    else:
        # if (previous_day_probe_anchor["asn_path"],previous_day_probe_experiment["asn_path"],probe["asn_path"], probe_2["asn_path"],ixp_info,identification_label) not in potentially_filtering_asns_invalid_died_length_2[day][id][asn]:
        a[day][id][asn].append((previous_day_probe_anchor["asn_path"], previous_day_probe_experiment["asn_path"], probe["asn_path"], probe_2["asn_path"], ixp_info, identification_label))
    return a

#This method checks if all probes had the same path and only 1 hop and returns the asn under test.
def perform_whitelist_1hop_new(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2):
    if len(probe["asn_path"]) == 2 and (probe_2["asn_path"] == probe["asn_path"] == previous_day_probe_anchor["asn_path"] == previous_day_probe_experiment["asn_path"]) and probe['reached_PEERING'] == True:  # check that we don´t include route divergence cases
        return probe["asn_path"][:-1][0]
    return None

def perform_traceroute_eval_case_2a_new(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2):
    # This is for VALID SUCCESS - INVALID FAIL - CASE 2a
    #print("Traceroute - VALID OK / INVALID FAIL - Only 1 hop")

    if (len(probe["asn_path"]) == 2 and  # Length == 2 for Valid
        '*' not in probe["asn_path"] and
        probe['reached_PEERING'] == True and #Anchor invalid day could reach PEERING
        '*' not in previous_day_probe_anchor["asn_path"] and
        previous_day_probe_anchor["reached_PEERING"] == True and
        probe["asn_path"] == previous_day_probe_anchor["asn_path"] == previous_day_probe_experiment["asn_path"] and
        not (probe_2["asn_path"][-1:] == ['47065'])): #Experiment prefix did not reach
            #occurences += 1

            print('Identified')
            return probe["asn_path"][:-1][0]

    return None

def perform_traceroute_eval_case_2b_new(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2):
    # This is for VALID SUCCESS - INVALID Route divergence - CASE 2b
    #print("Traceroute - VALID OK / INVALID Route divergence - Only 1 hop (for valid)")
    if (len(probe["asn_path"]) == 2 and  # Length == 2 for Valid
        '*' not in probe["asn_path"] and
        probe['reached_PEERING'] == True and #Anchor invalid day could reach PEERING
        '*' not in previous_day_probe_anchor["asn_path"] and
        previous_day_probe_anchor["reached_PEERING"] == True and
        probe["asn_path"] == previous_day_probe_anchor["asn_path"] == previous_day_probe_experiment["asn_path"] and
        (probe_2["asn_path"][-1:] == ['47065'])): #Experiment prefix did not reach

            # Valid == 2, Invalid fully resolved == length >2, Invalid partially resolved == length > 3
            # This is to avoid cases in which we see: TestedAS - * - 47065
            if ('*' not in probe_2["asn_path"] and len(probe_2["asn_path"]) > 2) or (
                    '*' in probe_2["asn_path"] and len(probe_2["asn_path"]) > 3):

                print('Flag')
                return probe["asn_path"][:-1][0]

    return None

def perform_whitelist_2hops_new(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2):
    if len(probe["asn_path"]) > 2 and (probe_2["asn_path"] == probe["asn_path"] == previous_day_probe_anchor["asn_path"] == previous_day_probe_experiment["asn_path"]) and probe['reached_PEERING'] == True:  # check that we don´t include route divergence cases
        return probe["asn_path"][:-1]
    return None

def perform_traceroute_eval_case_4a_new(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, traceroute, pop, day, id, potentially_filtering_asns_invalid_died_length_2, potentially_filtering_asns_invalid_diverged_length_2, folder_prefix):
    # This is for VALID SUCCESS - INVALID FAIL - CASE 4a
    # print("Traceroute - VALID OK / INVALID FAIL - 2+ hops")

    if (len(probe["asn_path"]) > 2 and  # Length > 2 for Valid
        '*' not in probe["asn_path"] and
        probe['reached_PEERING'] == True and #Anchor invalid day could reach PEERING
        '*' not in previous_day_probe_anchor["asn_path"] and
        previous_day_probe_anchor["reached_PEERING"] == True and
        probe["asn_path"] == previous_day_probe_anchor["asn_path"] == previous_day_probe_experiment["asn_path"] and
        '47065-MUX' not in probe_2["asn_path"] and #to avoid Day 1 Experiment   ['35714', '3326', '47065-MUX', '*', '*', '*', '*', '*', '*']
        not (probe_2["asn_path"][-1:] == ['47065'])): #Experiment prefix did not reach

            # Filter out all paths in which we already found one ROV AS
            found_rov_as = 0
            for asn in probe["asn_path"][:-1]:
                if asn in potentially_filtering_asns_invalid_died_length_2[day][id] or asn in potentially_filtering_asns_invalid_diverged_length_2[day][id]:
                    #print("FOUND ROV AS", asn)
                    found_rov_as = 1

            if found_rov_as == 0:  # Only do extensions to paths if it does not already contain a ROV AS
                # No ASN has yet been identified as filtering.
                # Now we need to check if we have valid + invalid responses from all intermediate hops. If this is true, we can conclude that the RIPE probe AS is filtering.

                resultset = set()
                for i in range(2, len(probe["asn_path"])):

                    #print(probe["asn_path"][0-i:]) #Show path snippet we are searching for now

                    # Find for this path a valid + invalid completed trace (meaning that there has not been ROV)
                    inside_probe_counter = -1
                    for inside_probe in traceroute[day][id]:
                        inside_probe_counter += 1
                        if inside_probe["asn_path"] == probe["asn_path"][0 - i:]:
                            inside_probe_2_counter = -1
                            inside_invalid_id = find_matching_measurement(traceroute[day], pop, "experiment",folder_prefix)
                            for inside_probe_2 in traceroute[day][inside_invalid_id]:  # Search for match in invalid set
                                inside_probe_2_counter += 1
                                if inside_probe['prb_id'] == inside_probe_2['prb_id']:
                                    if inside_probe_2["asn_path"] == probe["asn_path"][0 - i:]:
                                        #print()
                                        #print('Completed traces found (valid+invalid) ', probe["asn_path"][0-i:])
                                        #print()
                                        #print("Day " + str(day) + ", id: " + str(id) + ", probe_valid: " + str(inside_probe_counter) + " probe_invalid: " + str(inside_probe_2_counter))
                                        #print(inside_probe["asn_path"])
                                        #print(inside_probe_2["asn_path"])
                                        resultset.add(', '.join(str(e) for e in probe["asn_path"][0 - i:]))

                if len(resultset) == (len(probe["asn_path"]) - 2):
                    print()
                    print('Completely successful! ')
                    print(resultset)
                    print("Day 0 Anchor      ", previous_day_probe_anchor["asn_path"])
                    print("Day 0 Experiment  ", previous_day_probe_experiment["asn_path"])
                    print("Day 1 Anchor      ", probe["asn_path"])
                    print("Day 1 Experiment  ", probe_2["asn_path"])
                    print("ASN flagged: ", probe["asn_path"][0])

                    return probe["asn_path"][0]
    return None

def perform_traceroute_eval_case_4b_new(previous_day_probe_anchor, previous_day_probe_experiment, probe, probe_2, traceroute, pop, day, id, potentially_filtering_asns_invalid_died_length_2, potentially_filtering_asns_invalid_diverged_length_2, potentially_filtering_asns_invalid_died_length_more_than_2, folder_prefix):
    # This is for VALID SUCCESS - INVALID Route Divergence - CASE 4b
    #print("Traceroute - VALID OK / INVALID OK - 2+ hops")
    if (len(probe["asn_path"]) > 2 and  # Length > 2 for Valid
        '*' not in probe["asn_path"] and
        probe['reached_PEERING'] == True and #Anchor invalid day could reach PEERING
        '*' not in previous_day_probe_anchor["asn_path"] and
        previous_day_probe_anchor["reached_PEERING"] == True and
        probe["asn_path"] == previous_day_probe_anchor["asn_path"] == previous_day_probe_experiment["asn_path"] and
        '*' not in probe_2["asn_path"] and
        (probe_2["asn_path"][-1:] == ['47065']) and #Experiment prefix did reach
        probe["asn_path"] != probe_2["asn_path"]):  # Route divergence

            # Filter out all paths in which we already found one ROV AS
            found_rov_as = 0
            for asn in probe["asn_path"][:-1]:
                if asn in potentially_filtering_asns_invalid_died_length_2[day][id] or asn in potentially_filtering_asns_invalid_diverged_length_2[day][id] or asn in potentially_filtering_asns_invalid_died_length_more_than_2[day][id]:
                    #print("FOUND ROV AS", asn)
                    found_rov_as = 1

            if found_rov_as == 0:  # Only do extensions to paths if it does not already contain a ROV AS
                #We haven´t found any ROV asn so far. Substract prefix and suffix and if its only one AS remaining, flag it.

                tmp_path = probe["asn_path"]
                # Substracting prefix (same AS path for valid/invalid)
                for i in range(min(len(probe["asn_path"]), len(probe_2["asn_path"]))):
                    if probe["asn_path"][i] == probe_2["asn_path"][i]:
                        tmp_path = tmp_path[1:]
                    else:
                        break

                # Substracting suffix (same AS path for valid/invalid)
                length = len(probe["asn_path"])
                length2 = len(probe_2["asn_path"])
                for i in range(min(length, length2)):
                    if probe["asn_path"][length - i - 1] == probe_2["asn_path"][length2 - i - 1]:
                        #print(tmp_path)
                        tmp_path = tmp_path[:-1]
                    else:
                        break

                # Only use results if 1 AS remains (otherwise we can´t tell or would need to use statistics again)
                # print("tmp path: ", tmp_path)
                if len(tmp_path) == 1:
                    return tmp_path[0]
                    #print('ASN flagged as ROV-enforcing: ', asn)
    return None


def asns_on_invalid_paths(traceroute, folder_prefix):
    not_filtering_asns = {}

    not_filtering_asns[1] = {}

    for id in traceroute[1]:
        measurement = read_pickled_measurement_metadata(id, folder_prefix)
        #print(id)
        #print(measurement)
        if "experiment" not in measurement.description: continue
        print()
        print("ID " + str(id) + " - " + str(measurement.description))

        not_filtering_asns[1][id] = {}
        invalid_routes_counter = 0

        for probe in traceroute[1][id]:
            record_only_one_time = set()  # Record an ASN per route only once
            if '*' not in probe["asn_path"] and (probe["reached_PEERING"] == True):
                for asn in probe['asn_path'][:-1]:  # Add every ASN to whitelist except prefix origin
                    if asn not in record_only_one_time:
                        if asn not in not_filtering_asns[1][id]:
                            not_filtering_asns[1][id][asn] = 1
                        else:
                            not_filtering_asns[1][id][asn] += 1
                        record_only_one_time.add(asn)
                invalid_routes_counter += 1

                # print(probe['asn_path'])

        # Calculate percentages instead of absolute occurences:
        for asn in not_filtering_asns[1][id]:
            not_filtering_asns[1][id][asn] = round(
                (100 / invalid_routes_counter) * not_filtering_asns[1][id][asn], 2)

        # print("Based on number of routes: ", invalid_routes_counter)

        # print()
        # print("------------")
        # print("------------")
        # print("------------")
        # print()

        # print({k: v for k, v in sorted(not_filtering_asns[day][id].items(), key=lambda item: item[1], reverse=True)})
        # print()

    # for id in not_filtering_asns[day]:
    #    print(id)

    return not_filtering_asns


def remove_asns_below_threshold(not_filtering_asns, threshold):

    for run in not_filtering_asns[1]:

        # This section is removing all ASNs below a threshold: k
        for k in list(not_filtering_asns[1][run].keys()):
            if not_filtering_asns[1][run][k] < threshold:
                del not_filtering_asns[1][run][k]
                # print("POPPED", k)
            # else:
            #    print(k, not_filtering_asns[day][run][k]) #This prints all remaining ASNs above threshold

    return not_filtering_asns


def read_pickled_measurement_metadata(id, folder_prefix):
    for root, dirs, files in os.walk(folder_prefix):
        for file in files:
            if file.endswith(str(id) + ".pickle"):
                try:
                    measurement = pickle.load(open(os.path.join(root, file), "rb"))
                    return measurement
                except:
                    print("An error reading the PICKLE occured!")


    # Structure: case2a[day][id][asn]
    cases = [case2a, case2b, case4a, case4b]
    resultset = {}
    resultset_asns = {}
    total_unique_rov_per_day = {}
    total_per_day_case_2a = {}
    total_per_day_case_2b = {}
    total_per_day_case_4a = {}
    total_per_day_case_4b = {}

    index = 0
    resultset[index] = []
    resultset_asns[index] = []

    # This section generates the header for the csv file
    for pop in pops:
        if pop == "amsterdam ": pop = "amsterdam"  # To eliminate the whitespace in the end (not to get data from amsterdam_rs)
        resultset[index].extend((pop + "-case2a", pop + "-case2b", pop + "-case4a", pop + "-case4b", pop + "-whitelist-strict", pop + "-whitelist-loose", pop + "-remaining_strict", pop + "-remaining_loose"))
        resultset_asns[index].extend((pop + "-case2a", pop + "-case2b", pop + "-case4a", pop + "-case4b", pop + "-whitelist-strict", pop + "-whitelist-loose", pop + "-remaining_strict", pop + "-remaining_loose"))
    resultset[index].extend(("rov_unique_total_case2a", "rov_unique_total_case2a_minus_strict", "rov_unique_total_case2a_minus_loose"))
    resultset[index].extend(("rov_unique_total_case2b", "rov_unique_total_case2b_minus_strict", "rov_unique_total_case2b_minus_loose"))
    resultset[index].extend(("rov_unique_total_case4a", "rov_unique_total_case4a_minus_strict", "rov_unique_total_case4a_minus_loose"))
    resultset[index].extend(("rov_unique_total_case4b", "rov_unique_total_case4b_minus_strict", "rov_unique_total_case4b_minus_loose"))
    resultset[index].extend(("rov_unique_total", "rov_unique_total_minus_strict", "rov_unique_total_minus_loose"))  # Add totals in the end

    resultset_asns[index].extend(("rov_unique_total_case2a", "rov_unique_total_case2a_minus_strict", "rov_unique_total_case2a_minus_loose"))
    resultset_asns[index].extend(("rov_unique_total_case2b", "rov_unique_total_case2b_minus_strict", "rov_unique_total_case2b_minus_loose"))
    resultset_asns[index].extend(("rov_unique_total_case4a", "rov_unique_total_case4a_minus_strict", "rov_unique_total_case4a_minus_loose"))
    resultset_asns[index].extend(("rov_unique_total_case4b", "rov_unique_total_case4b_minus_strict", "rov_unique_total_case4b_minus_loose"))
    resultset_asns[index].extend(("rov_unique_total", "rov_unique_total_minus_strict", "rov_unique_total_minus_loose"))  # Add totals in the end

    # print(resultset[0])

    # Initialize resultset

    index += 1
    total_unique_rov_per_day[index] = {}
    total_unique_rov_per_day[index]["total"] = set()  # Initialize this from 0 onwards
    total_unique_rov_per_day[index]["strict"] = set()  # Initialize this from 0 onwards
    total_unique_rov_per_day[index]["loose"] = set()  # Initialize this from 0 onwards

    total_per_day_case_2a[index] = {}
    total_per_day_case_2a[index]["total"] = set()
    total_per_day_case_2a[index]["strict"] = set()
    total_per_day_case_2a[index]["loose"] = set()

    total_per_day_case_2b[index] = {}
    total_per_day_case_2b[index]["total"] = set()
    total_per_day_case_2b[index]["strict"] = set()
    total_per_day_case_2b[index]["loose"] = set()

    total_per_day_case_4a[index] = {}
    total_per_day_case_4a[index]["total"] = set()
    total_per_day_case_4a[index]["strict"] = set()
    total_per_day_case_4a[index]["loose"] = set()

    total_per_day_case_4b[index] = {}
    total_per_day_case_4b[index]["total"] = set()
    total_per_day_case_4b[index]["strict"] = set()
    total_per_day_case_4b[index]["loose"] = set()

    resultset[index] = []  # 0 is header, initialize this from 1 onwards
    resultset_asns[index] = []  # 0 is header, initialize this from 1 onwards

    for pop in pops:

        # print("**********")
        # print("**********")
        # print("PoP ", pop)
        # print("**********")
        # print("**********")
        # print((len(case2a)))

        day=1
        rov_all_cases = set()
        rov_case2a = set()
        rov_case2b = set()
        rov_case4a = set()
        rov_case4b = set()
        found_pop = 0
        case_counter = 0
        for case in cases:
            case_counter+=1
            #print(case)
            #print()
            #print()
            for id in case[day]:
                measurement = read_pickled_measurement_metadata(id, folder_prefix)

                if pop in measurement.description:
                    # print()
                    # print("ROV total: ", len(case[day][id].keys()))
                    # print("ROV: ", case[day][id].keys())
                    # print("Whitelisted loose: ", not_filtering_asns_loose[day][id+1].keys())
                    # print("Whitelisted strict: ", not_filtering_asns_strict[day][id + 1].keys())
                    # print("Removed loose FPs: ", case[day][id].keys() - (case[day][id].keys() - not_filtering_asns_loose[day][id+1].keys()))
                    # print("Remaining ROV: ", case[day][id].keys() - not_filtering_asns_loose[day][id+1].keys())
                    # print("Removed strict FPs: ", case[day][id].keys() - (case[day][id].keys() - not_filtering_asns_strict[day][id+1].keys()))
                    # print("Remaining ROV: ", case[day][id].keys() - not_filtering_asns_strict[day][id+1].keys())

                    found_pop = 1
                    resultset[index].append(len(case[day][id].keys()))
                    resultset_asns[index].append(list(case[day][id].keys()))
                    # print("PoP found, adding case. ")
                    [rov_all_cases.add(key) for key in case[day][id].keys()]

                    # save all cases per day separately
                    if case_counter == 1:[rov_case2a.add(key) for key in case[day][id].keys()]
                    elif case_counter == 2:[rov_case2b.add(key) for key in case[day][id].keys()]
                    elif case_counter == 3:[rov_case4a.add(key) for key in case[day][id].keys()]
                    elif case_counter == 4:[rov_case4b.add(key) for key in case[day][id].keys()]

        print("rov_all_cases total: ", len(rov_all_cases))
        print("rov_all_cases: ", rov_all_cases)

        for id in not_filtering_asns_strict[day]:
            measurement = read_pickled_measurement_metadata(id, folder_prefix)
            if pop in measurement.description and "experiment" in measurement.description:
                # print("PoP found, adding sums. ")
                resultset[index].append(len(not_filtering_asns_strict[day][id].keys()))  # Strict Whitelist ASNs
                resultset[index].append(len(not_filtering_asns_loose[day][id].keys()))  # Loose Whitelist ASNs
                resultset[index].append(len(rov_all_cases - not_filtering_asns_strict[day][id].keys()))  # Remaining ROV ASes (strict)
                resultset[index].append(len(rov_all_cases - not_filtering_asns_loose[day][id].keys()))  # Remaining ROV ASes (loose)

                resultset_asns[index].append(list(not_filtering_asns_strict[day][id].keys()))  # Strict Whitelist ASNs
                resultset_asns[index].append(list(not_filtering_asns_loose[day][id].keys()))  # Loose Whitelist ASNs
                resultset_asns[index].append(list(rov_all_cases - not_filtering_asns_strict[day][id].keys()))  # Remaining ROV ASes (strict)
                resultset_asns[index].append(list(rov_all_cases - not_filtering_asns_loose[day][id].keys()))  # Remaining ROV ASes (loose)

                total_per_day_case_2a[index]["total"].update(rov_case2a)
                total_per_day_case_2a[index]["strict"].update(rov_case2a - not_filtering_asns_strict[day][id].keys())  # Accumulating all ROV-flagged ASes (strict)
                total_per_day_case_2a[index]["loose"].update(rov_case2a - not_filtering_asns_loose[day][id].keys())  # Accumulating all ROV-flagged ASes (loose)

                total_per_day_case_2b[index]["total"].update(rov_case2b)
                total_per_day_case_2b[index]["strict"].update(rov_case2b - not_filtering_asns_strict[day][id].keys())  # Accumulating all ROV-flagged ASes (strict)
                total_per_day_case_2b[index]["loose"].update(rov_case2b - not_filtering_asns_loose[day][id].keys())  # Accumulating all ROV-flagged ASes (loose)

                total_per_day_case_4a[index]["total"].update(rov_case4a)
                total_per_day_case_4a[index]["strict"].update(rov_case4a - not_filtering_asns_strict[day][id].keys())  # Accumulating all ROV-flagged ASes (strict)
                total_per_day_case_4a[index]["loose"].update(rov_case4a - not_filtering_asns_loose[day][id].keys())  # Accumulating all ROV-flagged ASes (loose)

                total_per_day_case_4b[index]["total"].update(rov_case4b)
                total_per_day_case_4b[index]["strict"].update(rov_case4b - not_filtering_asns_strict[day][id].keys())  # Accumulating all ROV-flagged ASes (strict)
                total_per_day_case_4b[index]["loose"].update(rov_case4b - not_filtering_asns_loose[day][id].keys())  # Accumulating all ROV-flagged ASes (loose)

                total_unique_rov_per_day[index]["total"].update(rov_all_cases)
                total_unique_rov_per_day[index]["strict"].update(rov_all_cases - not_filtering_asns_strict[day][
                    id].keys())  # Accumulating all ROV-flagged ASes (strict)
                total_unique_rov_per_day[index]["loose"].update(rov_all_cases - not_filtering_asns_loose[day][
                    id].keys())  # Accumulating all ROV-flagged ASes (loose)

        # This is for PoPs that were added later on not to throw an error during parsing of resultset
        if found_pop == 0:
            print("Day " + str(day) + " - PoP not found: " + str(pop))
            resultset[index].extend((0, 0, 0, 0, 0, 0, 0, 0))
            resultset_asns[index].extend((0, 0, 0, 0, 0, 0, 0, 0))
            # print(resultset)

    # Add all ROV ASes to the final resultset per day
    # Resultset Numbers
    resultset[index].append(len(total_per_day_case_2a[day]["total"]))  # total == without removing whitelist
    resultset[index].append(len(total_per_day_case_2a[day]["strict"]))  # strict == strict whitelist removed
    resultset[index].append(len(total_per_day_case_2a[day]["loose"]))  # loose == loose whitelist removed

    resultset[index].append(len(total_per_day_case_2b[day]["total"]))  # total == without removing whitelist
    resultset[index].append(len(total_per_day_case_2b[day]["strict"]))  # strict == strict whitelist removed
    resultset[index].append(len(total_per_day_case_2b[day]["loose"]))  # loose == loose whitelist removed

    resultset[index].append(len(total_per_day_case_4a[day]["total"]))  # total == without removing whitelist
    resultset[index].append(len(total_per_day_case_4a[day]["strict"]))  # strict == strict whitelist removed
    resultset[index].append(len(total_per_day_case_4a[day]["loose"]))  # loose == loose whitelist removed

    resultset[index].append(len(total_per_day_case_4b[day]["total"]))  # total == without removing whitelist
    resultset[index].append(len(total_per_day_case_4b[day]["strict"]))  # strict == strict whitelist removed
    resultset[index].append(len(total_per_day_case_4b[day]["loose"]))  # loose == loose whitelist removed

    resultset[index].append(len(total_unique_rov_per_day[day]["total"]))  # total == without removing whitelist
    resultset[index].append(len(total_unique_rov_per_day[day]["strict"]))  # strict == strict whitelist removed
    resultset[index].append(len(total_unique_rov_per_day[day]["loose"]))  # loose == loose whitelist removed

    # Resultset ASNs

    resultset_asns[index].append(list(total_per_day_case_2a[day]["total"]))  # total == without removing whitelist
    resultset_asns[index].append(list(total_per_day_case_2a[day]["strict"]))  # strict == strict whitelist removed
    resultset_asns[index].append(list(total_per_day_case_2a[day]["loose"]))  # loose == loose whitelist removed

    resultset_asns[index].append(list(total_per_day_case_2b[day]["total"]))  # total == without removing whitelist
    resultset_asns[index].append(list(total_per_day_case_2b[day]["strict"]))  # strict == strict whitelist removed
    resultset_asns[index].append(list(total_per_day_case_2b[day]["loose"]))  # loose == loose whitelist removed

    resultset_asns[index].append(list(total_per_day_case_4a[day]["total"]))  # total == without removing whitelist
    resultset_asns[index].append(list(total_per_day_case_4a[day]["strict"]))  # strict == strict whitelist removed
    resultset_asns[index].append(list(total_per_day_case_4a[day]["loose"]))  # loose == loose whitelist removed

    resultset_asns[index].append(list(total_per_day_case_4b[day]["total"]))  # total == without removing whitelist
    resultset_asns[index].append(list(total_per_day_case_4b[day]["strict"]))  # strict == strict whitelist removed
    resultset_asns[index].append(list(total_per_day_case_4b[day]["loose"]))  # loose == loose whitelist removed

    resultset_asns[index].append(list(total_unique_rov_per_day[day]["total"]))  # total == without removing whitelist
    resultset_asns[index].append(list(total_unique_rov_per_day[day]["strict"]))  # strict == strict whitelist removed
    resultset_asns[index].append(list(total_unique_rov_per_day[day]["loose"]))  # loose == loose whitelist removed

    print(resultset)
    print()
    print(resultset_asns)
    print()

    """
    print()
    for day in total_unique_rov_per_day:
        print(len(total_unique_rov_per_day[day]["total"]))
        #print(total_unique_rov_per_day[day]["total"])

    print()
    for day in total_unique_rov_per_day:
        print(len(total_unique_rov_per_day[day]["strict"]))
        #print(total_unique_rov_per_day[day]["strict"])

    print()
    for day in total_unique_rov_per_day:
        print(len(total_unique_rov_per_day[day]["loose"]))
        #print(total_unique_rov_per_day[day]["loose"])
    """

    for i in resultset:
        print(len(resultset[i]))

    # This saves the number count (statistics) for each item (not the actual data)
    df = pd.DataFrame(data=resultset)
    df = df.T
    df.to_csv(header=False, index=True, path_or_buf=folder_prefix + "/" + date + "/results.csv", sep='\t')
    print("Done writing result file to: ", folder_prefix + "/" + date + "/results.csv")

    # This saves the actual ROV enforcing ASes and the whitelists (data)
    dump = json.dumps(resultset_asns)
    with open(folder_prefix + "/" + date + "/resultset_asns.json", 'w') as my_data_file:
        my_data_file.write(dump)

    return resultset, resultset_asns

def print_results_new(pops, successful_1_hop, case2a, case2b, successful_2plus_hop, case4a, case4b, not_filtering_asns_strict, not_filtering_asns_loose, folder_prefix, date):
    print(pops)
    cases = [case2a, case2b, case4a, case4b]
    resultset = {}
    resultset_asns = {}

    #This section generates the header for the csv file
    index = 0
    resultset[index] = []
    resultset_asns[index] = []
    for pop in pops:
        if pop == "amsterdam ": pop = "amsterdam" #To eliminate the whitespace in the end (not to get data from amsterdam_rs)
        if pop == "seattle ": pop = "seattle"  # To eliminate the whitespace in the end (not to get data from amsterdam_rs)
        resultset[index].extend((pop + "-1_hop_success", pop + "-case2a",pop + "-case2a_noIXP",pop + "-case2a_IXP"))
        resultset[index].extend((pop + "-case2b", pop + "-case2b_noIXP", pop + "-case2b_IXP"))
        resultset[index].extend((pop + "-2plus_hop_success", pop + "-case4a", pop + "-case4a_noIXP", pop + "-case4a_IXP"))
        resultset[index].extend((pop + "-case4b", pop + "-case4b_noIXP", pop + "-case4b_IXP"))
        #resultset[index].extend((pop+"-case2a", pop+"-case2b", pop+"-case4a", pop+"-case4b"))

        resultset_asns[index].extend((pop + "-1_hop_success", pop + "-case2a",pop + "-case2a_noIXP",pop + "-case2a_IXP"))
        resultset_asns[index].extend((pop + "-case2b", pop + "-case2b_noIXP", pop + "-case2b_IXP"))
        resultset_asns[index].extend((pop + "-2plus_hop_success", pop + "-case4a", pop + "-case4a_noIXP", pop + "-case4a_IXP"))
        resultset_asns[index].extend((pop + "-case4b", pop + "-case4b_noIXP", pop + "-case4b_IXP"))
        #resultset_asns[index].extend((pop+"-case2a", pop+"-case2b", pop+"-case4a", pop+"-case4b"))

    resultset[index].extend(("1_hop_successful_unique_total", "case2a_unique_total", "case2a_unique_total_minus_strict", "case2a_unique_total_minus_loose"))  # Add totals in the end
    resultset[index].extend(("case2b_unique_total", "case2b_unique_total_minus_strict", "case2b_unique_total_minus_loose"))  # Add totals in the end
    resultset[index].extend(("2plus_hop_successful_unique_total", "case4a_unique_total", "case4a_unique_total_minus_strict", "case4a_unique_total_minus_loose"))  # Add totals in the end
    resultset[index].extend(("case4b_unique_total", "case4b_unique_total_minus_strict", "case4b_unique_total_minus_loose"))  # Add totals in the end
    resultset[index].extend(("unique_total_whitelist_strict", "unique_total_whitelist_loose"))  # Add totals in the end
    resultset[index].extend(("all_successful_unique_total", "rov_unique_total", "rov_unique_total_minus_strict", "rov_unique_total_minus_loose")) #Add totals in the end

    resultset_asns[index].extend(("1_hop_successful_unique_total", "case2a_unique_total", "case2a_unique_total_minus_strict", "case2a_unique_total_minus_loose"))  # Add totals in the end
    resultset_asns[index].extend(("case2b_unique_total", "case2b_unique_total_minus_strict", "case2b_unique_total_minus_loose"))  # Add totals in the end
    resultset_asns[index].extend(("2plus_hop_successful_unique_total", "case4a_unique_total", "case4a_unique_total_minus_strict", "case4a_unique_total_minus_loose"))  # Add totals in the end
    resultset_asns[index].extend(("case4b_unique_total", "case4b_unique_total_minus_strict", "case4b_unique_total_minus_loose"))  # Add totals in the end
    resultset_asns[index].extend(("unique_total_whitelist_strict", "unique_total_whitelist_loose"))  # Add totals in the end
    resultset_asns[index].extend(("all_successful_unique_total", "rov_unique_total", "rov_unique_total_minus_strict", "rov_unique_total_minus_loose"))  # Add totals in the end

    #print(resultset)

    for day in case2a: #For every day
        resultset[day+1] = []
        resultset_asns[day+1] = []
        rov_all_cases_per_day = set()
        all_success_unique_per_day = set()
        one_hop_success_unique_per_day = set()
        two_plus_hop_success_unique_per_day = set()
        case2a_total_unique_per_day = set()
        case2b_total_unique_per_day = set()
        case4a_total_unique_per_day = set()
        case4b_total_unique_per_day = set()


        for pop in pops:
            found_pop = 0
            for id in case2a[day]:
                measurement = read_pickled_measurement_metadata(id, folder_prefix)
                if pop in measurement.description:
                    found_pop = 1
                    #print("Keys case2a for: ", id, measurement.description)
                    #print(case2a[day][id].keys())

                    #Write results into resultset
                    # resultset[day + 1].append(len(case2a[day][id].keys())) #all case2a
                    # for asn in case2a[day][id].keys():
                    #     for item in case2a[day][id][asn]:
                    #         if 'noIXP' in item:
                    #             resultset[day + 1].append(len(case2a[day][id].keys())) #noIXP case2a
                    #         else:
                    #             resultset[day + 1].append(len(case2a[day][id].keys())) #IXP case2a
                    #
                    #     #resultset[day + 1].append(#asns)
                    #
                    # resultset[day + 1].append(len(case2a[day][id].keys()))


                    # Collect asns for IXP / noIXP for each case

                    case2a_noIXP = set()
                    case2a_IXP = set()
                    for asn in case2a[day][id].keys():
                        for instance in case2a[day][id][asn]:
                            if 'noIXP' == instance[4]: case2a_noIXP.add(asn) # position for IXP or noIXP flag
                            elif 'crossing' in str(instance[4]): case2a_IXP.add(asn)  # position for IXP or noIXP flag
                            else: print('ERROR detected - no IXP information found: ', instance)
                    case2b_noIXP = set()
                    case2b_IXP = set()
                    for asn in case2b[day][id].keys():
                        for instance in case2b[day][id][asn]:
                            if 'noIXP' == instance[4]: case2b_noIXP.add(asn) # position for IXP or noIXP flag
                            elif 'crossing' in str(instance[4]): case2b_IXP.add(asn)  # position for IXP or noIXP flag
                            else:
                                print('ERROR detected - no IXP information found: ', instance)
                    case4a_noIXP = set()
                    case4a_IXP = set()
                    for asn in case4a[day][id].keys():
                        for instance in case4a[day][id][asn]:
                            if 'noIXP' == instance[4]: case4a_noIXP.add(asn) # position for IXP or noIXP flag
                            elif 'crossing' in str(instance[4]): case4a_IXP.add(asn)  # position for IXP or noIXP flag
                            else:
                                print('ERROR detected - no IXP information found: ', instance)
                    case4b_noIXP = set()
                    case4b_IXP = set()
                    for asn in case4b[day][id].keys():
                        for instance in case4b[day][id][asn]:
                            if 'noIXP' == instance[4]: case4b_noIXP.add(asn) # position for IXP or noIXP flag
                            elif 'crossing' in str(instance[4]): case4b_IXP.add(asn)  # position for IXP or noIXP flag
                            else:
                                print('ERROR detected - no IXP information found: ', instance)

                    # Add sums for IXP / noIXP for each case

                    resultset[day + 1].append(len(successful_1_hop[day][id].keys()))

                    resultset[day + 1].append(len(case2a[day][id].keys()))
                    resultset[day + 1].append(len(case2a_noIXP))
                    resultset[day + 1].append(len(case2a_IXP))

                    resultset[day + 1].append(len(case2b[day][id].keys()))
                    resultset[day + 1].append(len(case2b_noIXP))
                    resultset[day + 1].append(len(case2b_IXP))

                    resultset[day + 1].append(len(successful_2plus_hop[day][id].keys()))

                    resultset[day + 1].append(len(case4a[day][id].keys()))
                    resultset[day + 1].append(len(case4a_noIXP))
                    resultset[day + 1].append(len(case4a_IXP))

                    resultset[day + 1].append(len(case4b[day][id].keys()))
                    resultset[day + 1].append(len(case4b_noIXP))
                    resultset[day + 1].append(len(case4b_IXP))


                    # Add asns for IXP / noIXP for each case

                    resultset_asns[day + 1].append(list(successful_1_hop[day][id].keys()))

                    resultset_asns[day + 1].append(list(case2a[day][id].keys()))
                    resultset_asns[day + 1].append(list(case2a_noIXP))
                    resultset_asns[day + 1].append(list(case2a_IXP))

                    resultset_asns[day + 1].append(list(case2b[day][id].keys()))
                    resultset_asns[day + 1].append(list(case2b_noIXP))
                    resultset_asns[day + 1].append(list(case2b_IXP))

                    resultset_asns[day + 1].append(list(successful_2plus_hop[day][id].keys()))

                    resultset_asns[day + 1].append(list(case4a[day][id].keys()))
                    resultset_asns[day + 1].append(list(case4a_noIXP))
                    resultset_asns[day + 1].append(list(case4a_IXP))

                    resultset_asns[day + 1].append(list(case4b[day][id].keys()))
                    resultset_asns[day + 1].append(list(case4b_noIXP))
                    resultset_asns[day + 1].append(list(case4b_IXP))

                    all_success_unique_per_day.update(list(successful_1_hop[day][id].keys()))
                    all_success_unique_per_day.update(list(successful_2plus_hop[day][id].keys()))

                    rov_all_cases_per_day.update(list(case2a[day][id].keys()))
                    rov_all_cases_per_day.update(list(case2b[day][id].keys()))
                    rov_all_cases_per_day.update(list(case4a[day][id].keys()))
                    rov_all_cases_per_day.update(list(case4b[day][id].keys()))

                    one_hop_success_unique_per_day.update(list(successful_1_hop[day][id].keys()))
                    case2a_total_unique_per_day.update(list(case2a[day][id].keys()))
                    case2b_total_unique_per_day.update(list(case2b[day][id].keys()))

                    two_plus_hop_success_unique_per_day.update(list(successful_2plus_hop[day][id].keys()))
                    case4a_total_unique_per_day.update(list(case4a[day][id].keys()))
                    case4b_total_unique_per_day.update(list(case4b[day][id].keys()))

            # This is for PoPs that were added later on not to throw an error during parsing of resultset
            if found_pop == 0:
                print("Day " + str(day) + " - PoP not found: " + str(pop))
                resultset[day+1].extend((0, 0, 0, 0))
                resultset_asns[day+1].extend(([], [], [], []))
                # print(resultset)

        not_filtering_asns_strict_unique_total = set()
        not_filtering_asns_loose_unique_total = set()
        for id in not_filtering_asns_strict[day]:
            not_filtering_asns_strict_unique_total.update(list(not_filtering_asns_strict[day][id].keys()))
            not_filtering_asns_loose_unique_total.update(list(not_filtering_asns_loose[day][id].keys()))


        resultset[day + 1].append(len(one_hop_success_unique_per_day))

        resultset[day + 1].append(len(case2a_total_unique_per_day))
        resultset[day + 1].append(len(case2a_total_unique_per_day - not_filtering_asns_strict_unique_total))
        resultset[day + 1].append(len(case2a_total_unique_per_day - not_filtering_asns_loose_unique_total))

        resultset[day + 1].append(len(case2b_total_unique_per_day))
        resultset[day + 1].append(len(case2b_total_unique_per_day - not_filtering_asns_strict_unique_total))
        resultset[day + 1].append(len(case2b_total_unique_per_day - not_filtering_asns_loose_unique_total))

        resultset[day + 1].append(len(two_plus_hop_success_unique_per_day))

        resultset[day + 1].append(len(case4a_total_unique_per_day))
        resultset[day + 1].append(len(case4a_total_unique_per_day - not_filtering_asns_strict_unique_total))
        resultset[day + 1].append(len(case4a_total_unique_per_day - not_filtering_asns_loose_unique_total))

        resultset[day + 1].append(len(case4b_total_unique_per_day))
        resultset[day + 1].append(len(case4b_total_unique_per_day - not_filtering_asns_strict_unique_total))
        resultset[day + 1].append(len(case4b_total_unique_per_day - not_filtering_asns_loose_unique_total))

        resultset[day + 1].append(len(not_filtering_asns_strict_unique_total))
        resultset[day + 1].append(len(not_filtering_asns_loose_unique_total))

        resultset[day + 1].append(len(all_success_unique_per_day))

        resultset[day + 1].append(len(rov_all_cases_per_day))
        resultset[day + 1].append(len(rov_all_cases_per_day - not_filtering_asns_strict_unique_total))
        resultset[day + 1].append(len(rov_all_cases_per_day - not_filtering_asns_loose_unique_total))



        resultset_asns[day + 1].append(list(one_hop_success_unique_per_day))

        resultset_asns[day + 1].append(list(case2a_total_unique_per_day))
        resultset_asns[day + 1].append(list(case2a_total_unique_per_day - not_filtering_asns_strict_unique_total))
        resultset_asns[day + 1].append(list(case2a_total_unique_per_day - not_filtering_asns_loose_unique_total))

        resultset_asns[day + 1].append(list(case2b_total_unique_per_day))
        resultset_asns[day + 1].append(list(case2b_total_unique_per_day - not_filtering_asns_strict_unique_total))
        resultset_asns[day + 1].append(list(case2b_total_unique_per_day - not_filtering_asns_loose_unique_total))

        resultset_asns[day + 1].append(list(two_plus_hop_success_unique_per_day))

        resultset_asns[day + 1].append(list(case4a_total_unique_per_day))
        resultset_asns[day + 1].append(list(case4a_total_unique_per_day - not_filtering_asns_strict_unique_total))
        resultset_asns[day + 1].append(list(case4a_total_unique_per_day - not_filtering_asns_loose_unique_total))

        resultset_asns[day + 1].append(list(case4b_total_unique_per_day))
        resultset_asns[day + 1].append(list(case4b_total_unique_per_day - not_filtering_asns_strict_unique_total))
        resultset_asns[day + 1].append(list(case4b_total_unique_per_day - not_filtering_asns_loose_unique_total))

        resultset_asns[day + 1].append(list(not_filtering_asns_strict_unique_total))
        resultset_asns[day + 1].append(list(not_filtering_asns_loose_unique_total))

        resultset_asns[day + 1].append(list(all_success_unique_per_day))

        resultset_asns[day + 1].append(list(rov_all_cases_per_day))
        resultset_asns[day + 1].append(list(rov_all_cases_per_day - not_filtering_asns_strict_unique_total))
        resultset_asns[day + 1].append(list(rov_all_cases_per_day - not_filtering_asns_loose_unique_total))



    for i in resultset:
        print("Length resultset: ", len(resultset[i]))


    for i in resultset:
        print(resultset[i])

    #This saves the number count (statistics) for each item (not the actual data)
    df = pd.DataFrame(data=resultset)
    df = df.T
    df.to_csv(header=False, index=True, path_or_buf=folder_prefix + "/" + date + "/resultset.csv", sep='\t')

    print()
    for i in resultset_asns:
        print("Length resultset asns: ", len(resultset_asns[i]))

    #print(resultset_asns)

    # This saves the actual ROV enforcing ASes and the whitelists (data)
    dump = json.dumps(resultset_asns)
    with open(folder_prefix + "/" + date + "/resultset_asns.json", 'w') as my_data_file:
        my_data_file.write(dump)

    #print(case2a[0][23836064].keys())

    #print(resultset)

    return resultset, resultset_asns


def read_measurement_ids(date, previous_day, folder_prefix, type):
    measurement_ids = {}

    #Read actual day (invalid)
    with open(folder_prefix+"/"+date+"/"+type+"/measurement_ids.json", "r") as read_file:
        measurement_ids[1] = json.load(read_file)

    #Read previous day (valid)
    with open(folder_prefix+"/"+previous_day+"/"+type+"/measurement_ids.json", "r") as read_file:
        measurement_ids[0] = json.load(read_file)
    return measurement_ids

def fetch_measurement_data(ids, date, previous_day, folder_prefix, type):
    #actual day
    for id in ids[1]:
        if not os.path.isfile(folder_prefix + "/" + date + "/" + type + "/" + str(id) + ".json"):
            kwargs = {
                "msm_id": id,
                #        "start": datetime(2015, 05, 19),
                #        "stop": datetime(2015, 05, 20),
                #        "probe_ids": [1,2,3,4]
            }

            is_success, results = AtlasResultsRequest(**kwargs).create()

            if is_success:

                counter_success = 0
                counter_error = 0

                measurement = Measurement(id=id)

                print('Measurement: ', id)
                print('Description: ', measurement.description)
                print('Measurement state: ', measurement.status)

                # This saves the measurement data
                dump = json.dumps(results)
                with open(folder_prefix + "/" + date + "/" + type + "/" + str(id) + ".json", 'w') as my_data_file:
                    my_data_file.write(dump)

                # This pickles the measurement meta data
                if os.path.isfile(folder_prefix + "/" + date + "/" + type + "/" + str(id) + ".pickle"):
                    pass
                else:
                    # Dirty hack since we needed to decrease these numbers each by one as there is one foreign measurement inbetween
                    pickle.dump(measurement, open(folder_prefix + "/" + date + "/" + type + "/" + str(id) + ".pickle", "wb"))

                print("SUCCESS fetching RIPE Atlas measurment: ", id)
            else:
                print("ERROR fetching RIPE Atlas measurment: ", id)


    #previous day
    for id in ids[0]:
        if not os.path.isfile(folder_prefix + "/" + previous_day + "/" + type + "/" + str(id) + ".json"):
            kwargs = {
                "msm_id": id,
                #        "start": datetime(2015, 05, 19),
                #        "stop": datetime(2015, 05, 20),
                #        "probe_ids": [1,2,3,4]
            }

            is_success, results = AtlasResultsRequest(**kwargs).create()

            if is_success:

                counter_success = 0
                counter_error = 0

                measurement = Measurement(id=id)

                print('Measurement: ', id)
                print('Description: ', measurement.description)
                print('Measurement state: ', measurement.status)

                # This saves the measurement data
                dump = json.dumps(results)
                with open(folder_prefix + "/" + previous_day + "/" + type + "/" + str(id) + ".json", 'w') as my_data_file:
                    my_data_file.write(dump)

                # This pickles the measurement meta data
                if os.path.isfile(folder_prefix + "/" + previous_day + "/" + type + "/" + str(id) + ".pickle"):
                    pass
                else:
                    # Dirty hack since we needed to decrease these numbers each by one as there is one foreign measurement inbetween
                    pickle.dump(measurement, open(folder_prefix + "/" + previous_day + "/" + type + "/" + str(id) + ".pickle", "wb"))

                print("SUCCESS fetching RIPE Atlas measurment: ", id)
            else:
                print("ERROR fetching RIPE Atlas measurment: ", id)

def identify_ixp_crossings(folder_prefix, date, previous_day, traceroute):

    print()
    print("Started IXP Crossing Identification")

    # Identify IXP Crossing by using the traixroute tool
    for day in traceroute:
        print()
        print("DAY: ", day)
        for id in traceroute[day]:
            print("Started TraIXroute for Measurement: ", id)
            blockPrint()
            if day == 0:
                json_data = run_traixroute(folder_prefix + "/" + previous_day + "/traceroute/" + str(id) + ".json")
            elif day == 1:
                json_data = run_traixroute(folder_prefix + "/" + date + "/traceroute/" + str(id) + ".json")
            enablePrint()
            json_data_tmp = []
            [json_data_tmp.append(entry) for entry in itertools.chain.from_iterable(json_data)] #transform results array from traixroute with #cores in arrays to #items in array
            for probe,ixp_probe in zip(traceroute[day][id],json_data_tmp): #iterate over both arrays at the same time
                if "ixp_crossings" in ixp_probe:
                    probe['ixp_crossings'] = ixp_probe['ixp_crossings']
                else:
                    probe['ixp_crossings'] = None

    print("Finished IXP Crossing Identification")

    return traceroute

def transform_ips_to_asns(folder_prefix, date, previous_day, traceroute, measurement_ids, probes_to_asn):
    print()
    print("Started IP-ASN Translation")
    #args = parse_arguments(args)
    #ip_to_asn_file = args.input

    timestamp = date
    ip_to_asn_cache = {}
    ips = ip_to_asn.extract_all_ips(traceroute)
    ip_to_asn_cache, ips = ip_to_asn.resolve_private_ips(ips, ip_to_asn_cache) #Private IPs
    ip_to_asn_cache, ips = ip_to_asn.resolve_peering_ips(ips, ip_to_asn_cache) #PEERING IPs
    ip_to_asn_cache = ip_to_asn.resolve_cymru_ips(ips, ip_to_asn_cache, timestamp, date, folder_prefix) #The rest to Cymru
    ip_to_asn_cache = ip_to_asn.resolve_pyasn_ips(ips, ip_to_asn_cache) # Fill gaps with pyasn
    ip_to_asn.determine_missing_ips(ips, ip_to_asn_cache) # remaining IPs

    ip_to_asn_file = folder_prefix + "/" + date + "/" + timestamp + "_ip_to_asn_cache.json"

    # Write dict to file
    with open(ip_to_asn_file, "w") as write_file:
        json.dump(ip_to_asn_cache, write_file)

    # This part translates IP paths to ASN paths and also updates the json files accordingly
    # by adding an "asn_path" section to each measurement iteration which holds the shortened AS path
    traceroute = ip_to_asn.translate_ip_to_asn_paths(traceroute, ip_to_asn_cache, probes_to_asn)
    print("Finished IP-ASN Translation")

    return traceroute

def calculate_ixp_identification_success_rate(pop, traceroute, folder_prefix):
    print("**********")
    print("**********")
    print("Calculate IXP identification success rate for PoP: ", pop)
    print("**********")
    print("**********")

    counter_successful_TR = 0
    counter_successful_identification = 0

    for id in traceroute[1]:
        measurement = read_pickled_measurement_metadata(id, folder_prefix)
        #print(measurement.description)
        if "experiment" in measurement.description: continue
        if pop in measurement.description:
            print("Analyzing measurement: ", measurement.description)
            for probe in traceroute[1][id]:
                if probe['reached_PEERING'] == True:
                    counter_successful_TR += 1
                    if probe["ixp_crossings"] != None:
                        counter_successful_identification += 1
                        print(probe["ixp_crossings"])
            break #stop loop after the correct measurement has been found and analysis is finished

    print("Counter successful TR: ", counter_successful_TR)
    print("Counter successful identifications: ", counter_successful_identification)
    success_rate_anchor = 0
    if counter_successful_TR != 0:
        success_rate_anchor = 100 / counter_successful_TR * counter_successful_identification
    print("Share: 100/" + str(counter_successful_TR) + " * " + str(counter_successful_identification) + " = " + str(success_rate_anchor) + "%")

    return success_rate_anchor

def load_pcaps(folder_prefix, date, previous_day):
    print('Loading pcaps')
    tcpdump_seattle_day1 = 'tcpdump_'+ date.strftime("%Y") +'-'+ date.strftime("%m") +'-'+ date.strftime("%d") +'_0001.tap1'  #second day, pcap seattle
    tcpdump_amsterdam_day1 = 'tcpdump_'+ date.strftime("%Y") +'-'+ date.strftime("%m") +'-'+ date.strftime("%d") +'_0001.tap5'  #second day, pcap ams
    tcpdump_isi_day1 = 'tcpdump_' + date.strftime("%Y") + '-' + date.strftime("%m") + '-' + date.strftime("%d") + '_0001.tap2'  # second day, pcap ams
    tcpdump_grnet_day1 = 'tcpdump_' + date.strftime("%Y") + '-' + date.strftime("%m") + '-' + date.strftime("%d") + '_0001.tap9'  # second day, pcap ams
    tcpdump_gatech_day1 = 'tcpdump_' + date.strftime("%Y") + '-' + date.strftime("%m") + '-' + date.strftime("%d") + '_0001.tap6'  # second day, pcap ams
    tcpdump_uw_day1 = 'tcpdump_' + date.strftime("%Y") + '-' + date.strftime("%m") + '-' + date.strftime("%d") + '_0001.tap10'  # second day, pcap ams

    tcpdump_seattle_day0 = 'tcpdump_'+ previous_day.strftime("%Y") +'-'+ previous_day.strftime("%m") +'-'+ previous_day.strftime("%d") +'_0001.tap1'  #second day, pcap seattle
    tcpdump_amsterdam_day0 = 'tcpdump_'+ previous_day.strftime("%Y") +'-'+ previous_day.strftime("%m") +'-'+ previous_day.strftime("%d") +'_0001.tap5'  #second day, pcap ams
    tcpdump_isi_day0 = 'tcpdump_'+ previous_day.strftime("%Y") +'-'+ previous_day.strftime("%m") +'-'+ previous_day.strftime("%d") +'_0001.tap2'  #second day, pcap ams
    tcpdump_grnet_day0 = 'tcpdump_'+ previous_day.strftime("%Y") +'-'+ previous_day.strftime("%m") +'-'+ previous_day.strftime("%d") +'_0001.tap9'  #second day, pcap ams
    tcpdump_gatech_day0 = 'tcpdump_'+ previous_day.strftime("%Y") +'-'+ previous_day.strftime("%m") +'-'+ previous_day.strftime("%d") +'_0001.tap6'  #second day, pcap ams
    tcpdump_uw_day0 = 'tcpdump_'+ previous_day.strftime("%Y") +'-'+ previous_day.strftime("%m") +'-'+ previous_day.strftime("%d") +'_0001.tap10'  #second day, pcap ams

    date = date.strftime('%Y%m%d')
    previous_day = previous_day.strftime('%Y%m%d')

    pcap_recordings = {}
    pcap_recordings[0] = {}
    print('Seattle day0 pcap info: ')
    with open(folder_prefix + '/' + previous_day + '/traceroute/pcaps/' + tcpdump_seattle_day0 + '.err', "r") as read_file:
        for line in read_file:
            print(line)
    pcap_recordings[0]['seattle'] = rdpcap(folder_prefix + '/' + previous_day + '/traceroute/pcaps/' + tcpdump_seattle_day0 + '.pcap')
    print()

    print('AMS day0 pcap info: ')
    with open(folder_prefix + '/' + previous_day + '/traceroute/pcaps/' + tcpdump_amsterdam_day0 + '.err', "r") as read_file:
        for line in read_file:
            print(line)
    pcap_recordings[0]['ams'] = rdpcap(folder_prefix + '/' + previous_day + '/traceroute/pcaps/' + tcpdump_amsterdam_day0 + '.pcap')
    print()

    print('isi day0 pcap info: ')
    with open(folder_prefix + '/' + previous_day + '/traceroute/pcaps/' + tcpdump_isi_day0 + '.err', "r") as read_file:
        for line in read_file:
            print(line)
    pcap_recordings[0]['isi'] = rdpcap(folder_prefix + '/' + previous_day + '/traceroute/pcaps/' + tcpdump_isi_day0 + '.pcap')
    print()

    print('gatech day0 pcap info: ')
    with open(folder_prefix + '/' + previous_day + '/traceroute/pcaps/' + tcpdump_gatech_day0 + '.err', "r") as read_file:
        for line in read_file:
            print(line)
    pcap_recordings[0]['gatech'] = rdpcap(folder_prefix + '/' + previous_day + '/traceroute/pcaps/' + tcpdump_gatech_day0 + '.pcap')
    print()

    print('grnet day0 pcap info: ')
    with open(folder_prefix + '/' + previous_day + '/traceroute/pcaps/' + tcpdump_grnet_day0 + '.err', "r") as read_file:
        for line in read_file:
            print(line)
    pcap_recordings[0]['grnet'] = rdpcap(folder_prefix + '/' + previous_day + '/traceroute/pcaps/' + tcpdump_grnet_day0 + '.pcap')
    print()

    print('uw day0 pcap info: ')
    with open(folder_prefix + '/' + previous_day + '/traceroute/pcaps/' + tcpdump_uw_day0 + '.err', "r") as read_file:
        for line in read_file:
            print(line)
    pcap_recordings[0]['uw'] = rdpcap(folder_prefix + '/' + previous_day + '/traceroute/pcaps/' + tcpdump_uw_day0 + '.pcap')
    print()

    #now day 1

    print('Seattle day1 pcap info: ')
    pcap_recordings[1] = {}
    with open(folder_prefix + '/' + date + '/traceroute/pcaps/' + tcpdump_seattle_day1 + '.err', "r") as read_file:
        for line in read_file:
            print(line)
    pcap_recordings[1]['seattle'] = rdpcap(folder_prefix + '/' + date + '/traceroute/pcaps/' + tcpdump_seattle_day1 + '.pcap')

    print('AMS day1 pcap info: ')
    with open(folder_prefix + '/' + date + '/traceroute/pcaps/' + tcpdump_amsterdam_day1 + '.err', "r") as read_file:
        for line in read_file:
            print(line)
    pcap_recordings[1]['ams'] = rdpcap(folder_prefix + '/' + date + '/traceroute/pcaps/' + tcpdump_amsterdam_day1 + '.pcap')

    print('isi day1 pcap info: ')
    with open(folder_prefix + '/' + date + '/traceroute/pcaps/' + tcpdump_isi_day1 + '.err', "r") as read_file:
        for line in read_file:
            print(line)
    pcap_recordings[1]['isi'] = rdpcap(folder_prefix + '/' + date + '/traceroute/pcaps/' + tcpdump_isi_day1 + '.pcap')

    print('gatech day1 pcap info: ')
    with open(folder_prefix + '/' + date + '/traceroute/pcaps/' + tcpdump_gatech_day1 + '.err', "r") as read_file:
        for line in read_file:
            print(line)
    pcap_recordings[1]['gatech'] = rdpcap(folder_prefix + '/' + date + '/traceroute/pcaps/' + tcpdump_gatech_day1 + '.pcap')

    print('grnet day1 pcap info: ')
    with open(folder_prefix + '/' + date + '/traceroute/pcaps/' + tcpdump_grnet_day1 + '.err', "r") as read_file:
        for line in read_file:
            print(line)
    pcap_recordings[1]['grnet'] = rdpcap(folder_prefix + '/' + date + '/traceroute/pcaps/' + tcpdump_grnet_day1 + '.pcap')

    print('uw day1 pcap info: ')
    with open(folder_prefix + '/' + date + '/traceroute/pcaps/' + tcpdump_uw_day1 + '.err', "r") as read_file:
        for line in read_file:
            print(line)
    pcap_recordings[1]['uw'] = rdpcap(folder_prefix + '/' + date + '/traceroute/pcaps/' + tcpdump_uw_day1 + '.pcap')

    print('Done loading pcaps')
    return pcap_recordings


def main(args):
    start = normal_time.time() #Measure time

    # args = parse_arguments(args)
    #date_input = "20201208"
    date_input = "20210719" #input 2nd day
    date_raw = datetime.strptime(date_input, '%Y%m%d')
    previous_day_raw = date_raw - timedelta(days=1)
    date = date_raw.strftime('%Y%m%d')
    previous_day = previous_day_raw.strftime('%Y%m%d')

    # ip_to_asn_file = args.ip_to_asn_file
    folder_prefix = "Atlas/annet"

    #probes_info = "Atlas/20201205.json" #Immer 1 Tag vor den beiden Messtagen, also 3 Tage vor date_input
    probes_info = "Atlas/20210626.json"
    with open(probes_info, "r") as read_file: probes_file = json.load(read_file)
    probes_to_asn = load_probes_info(probes_info)

    traceroute_ids = read_measurement_ids(date, previous_day, folder_prefix, "traceroute")
    http_ids = read_measurement_ids(date, previous_day, folder_prefix, "http")

    fetch_measurement_data(traceroute_ids, date, previous_day, folder_prefix, "traceroute")
    fetch_measurement_data(http_ids, date, previous_day, folder_prefix, "http")

    # measurement_ids[day]["http"|"traceroute"] = [numbers]
    measurement_ids = load_ids(traceroute_ids, http_ids)

    experiment_switch = False

    if experiment_switch == False:
        http, traceroute = load_measurements(measurement_ids, folder_prefix, date, previous_day) #traceroute[0|1]
        traceroute = transform_ips_to_asns(folder_prefix, date, previous_day, traceroute, measurement_ids, probes_to_asn) # update measurements with asn_path and reached_PEERING flag
        #pickle.dump(traceroute, open(folder_prefix + "/" + date + "/traceroute_test.pickle", "wb"))

        # This next part can be used if IP-> ASN happened already and cache should be reused.
        #with open(folder_prefix + "/" + date + "/" + date + "_ip_to_asn_cache.json") as json_file:
        #    ip_to_asn_cache = json.load(json_file)
        #traceroute = ip_to_asn.translate_ip_to_asn_paths(traceroute, ip_to_asn_cache, probes_to_asn)

        #Load pcaps to check if probes actually reached PEERING
        pcap_recordings = load_pcaps(folder_prefix, date_raw, previous_day_raw)
        traceroute = ip_to_asn.reached_PEERING(traceroute, folder_prefix, probes_file, pcap_recordings)

        traceroute = identify_ixp_crossings(folder_prefix, date, previous_day, traceroute) # update measurements with ixp_crossings
        pickle.dump(traceroute, open(folder_prefix + "/" + date + "/traceroute.pickle", "wb"))
        ip_to_asn.save_asn_path_to_updated_file(measurement_ids, traceroute, folder_prefix, date, previous_day) #save updated measurements to file
    http, traceroute = load_updated_measurements(measurement_ids, folder_prefix, date, previous_day) #Load them again...somehow there is a bug and it only works with reloading all results...
    print("Done loading measurement data")


    """
    # This method calculates the success rate of IXP identification for a given pop. It only takes successful traceroutes into account and return the percentage of ASs an IXP was identified.
    # success_rate_anchor = calculate_ixp_identification_success_rate('amsterdam ', traceroute, folder_prefix)
    """


    # This section extracts ASNs from paths that are RPKI invalid.
    # The second function removes all ASNs from that list which are below the threshold (in percent)
    print("Identify not_filtering ASNs")
    if experiment_switch == False:
        not_filtering_asns_strict = asns_on_invalid_paths(traceroute, folder_prefix)
        pickle.dump(not_filtering_asns_strict, open(folder_prefix + "/" + date + "/not_filtering_asns_strict.pickle", "wb"))
    else:
        not_filtering_asns_strict = pickle.load(open(folder_prefix + "/" + date + "/not_filtering_asns_strict.pickle", "rb")) # TODO: Temporary!

    # show_asns_on_invalid_paths_in_graph(not_filtering_asns)
    if experiment_switch == False:
        not_filtering_asns_loose = remove_asns_below_threshold(copy.deepcopy(not_filtering_asns_strict), 2)  # Remove routes that are on less than x percent seen (noise)
        pickle.dump(not_filtering_asns_loose, open(folder_prefix + "/" + date + "/not_filtering_asns_loose.pickle", "wb"))
    else:
        not_filtering_asns_loose = pickle.load(open(folder_prefix + "/" + date + "/not_filtering_asns_loose.pickle", "rb"))  # TODO: Temporary!
    print("DONE identifying not_filtering ASNs")

    #
    # Case1: 1 hop - Valid OK / Invalid OK
    # Case2a: 1 hop - Valid OK / Invalid FAIL
    # Case2b: 1 hop - Valid OK / Invalid OK (Route divergence)
    # Case3: 2+ hop - Valid OK / Invalid OK
    # Case4a: 2+ hop - Valid OK / Invalid FAIL
	# Case4b: 2+ hop - Valid OK / Invalid OK (Route divergence)

    if experiment_switch == False:
        #This method extracts all traces (day0 anchor/experiment and day1 anchor/experiment)
        all_traces = extract_all_traces(traceroute, folder_prefix, date)
        pickle.dump(all_traces, open(folder_prefix + "/" + date + "/all_traces.pickle", "wb"))

        print("Started ROV identifications")
        successful_1_hop = eval_whitelist_1hop(all_traces)
        case2a = eval_case_2a(all_traces)
        case2b = eval_case_2b(all_traces)
        successful_2plus_hop = eval_whitelist_2hops(all_traces)
        case4a = eval_case_4a(all_traces, traceroute, case2a, case2b, folder_prefix)
        case4b = eval_case_4b(all_traces, traceroute, case2a, case2b, case4a, folder_prefix)
        print("Finished ROV identifications")
        # print("")
        # case2a, successful_1_hop = perform_traceroute_eval_case_2a(traceroute, folder_prefix, date)
        pickle.dump(case2a, open(folder_prefix + "/" + date + "/case2a.pickle", "wb"))
        pickle.dump(successful_1_hop, open(folder_prefix + "/" + date + "/successful_1_hop.pickle", "wb"))
        #print("Done Case2a")
        #
        # case2b = perform_traceroute_eval_case_2b(traceroute, folder_prefix, date)
        pickle.dump(case2b, open(folder_prefix + "/" + date + "/case2b.pickle", "wb"))
        # print("Done Case2b")
        #
        # case4a, successful_2plus_hop = perform_traceroute_eval_case_4a(traceroute, case2a, case2b, folder_prefix)
        pickle.dump(case4a, open(folder_prefix + "/" + date + "/case4a.pickle", "wb"))
        pickle.dump(successful_2plus_hop, open(folder_prefix + "/" + date + "/successful_2plus_hop.pickle", "wb"))
        # print("Done Case4a")
        #
        # case4b = perform_traceroute_eval_case_4b(traceroute, case2a, case2b, case4a, folder_prefix)
        pickle.dump(case4b, open(folder_prefix + "/" + date + "/case4b.pickle", "wb"))
        # print("Done Case4b")
        # # TODO: Implement direct PEERING peers check here! Currently it is in case2a and case2b

    else:
        # This method loads all traces (day0 anchor/experiment and day1 anchor/experiment)
        all_traces = pickle.load(open(folder_prefix + "/" + date + "/all_traces.pickle", "rb"))

        successful_1_hop = pickle.load(open(folder_prefix + "/" + date + "/successful_1_hop.pickle", "rb"))  # TODO: Temporary!
        print("Read successful_1_hop")
        case2a = pickle.load(open(folder_prefix + "/" + date + "/case2a.pickle", "rb"))  # TODO: Temporary!
        print("Read Case2a")
        case2b = pickle.load(open(folder_prefix + "/" + date + "/case2b.pickle", "rb"))  # TODO: Temporary!
        print("Read Case2b")
        successful_2plus_hop = pickle.load(open(folder_prefix + "/" + date + "/successful_2plus_hop.pickle", "rb"))  # TODO: Temporary!
        print("Read successful_2plus_hop")
        case4a = pickle.load(open(folder_prefix + "/" + date + "/case4a.pickle", "rb"))  # TODO: Temporary!
        print("Read Case4a")
        case4b = pickle.load(open(folder_prefix + "/" + date + "/case4b.pickle", "rb"))  # TODO: Temporary!
        print("Read Case4b")

    pops = ["seattle_RS", "seattle_wo_RS", "amsterdam_wo_RS", "amsterdam_RS", "gatech", "uw", "grnet", "isi"]  # TMA2021 Paper new

    resultset, resultset_asns = print_results_new(pops, successful_1_hop, case2a, case2b, successful_2plus_hop, case4a, case4b, not_filtering_asns_strict, not_filtering_asns_loose, folder_prefix, date)
    pickle.dump(resultset_asns, open(folder_prefix + "/" + date + "/resultset_asns.pickle", "wb"))

    #End time measurement
    end = normal_time.time()
    print()
    print("Time seconds: ", end - start)
    print("Time minutes: ", (end - start) / 60)
	
	
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
