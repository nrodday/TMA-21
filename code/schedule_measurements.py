__author__ = "Nils Rodday"
__copyright__ = "Copyright 2019"
__credits__ = ["Nils Rodday"]
__email__ = "nils.rodday@unibw.de"
__status__ = "Experimental"

#Get input list from https://ftp.ripe.net/ripe/atlas/probes/archive/2021/04/

import sys
import argparse
import json
import math
from ipwhois import IPWhois
from calendar import timegm
import os
import pickle

import datetime
from ripe.atlas.cousteau import (
  Ping,
  Http,
  Traceroute,
  AtlasSource,
  AtlasCreateRequest,
  AtlasResultsRequest,
  ProbeRequest
)

ATLAS_API_KEY = "" #Enter Key!
#ATLAS_API_KEY = "testing" #Change DAYs!

def parse_arguments(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="RIPE Atlas probes file")
    return parser.parse_args(args)

def probe_selection(RIPE_probes, probes_behind_middleboxes):

    # probes = ProbeRequest()
    #
    # for probe in probes:
    #     print(probe["id"])
    #
    # # Print total count of found probes
    # print(probes.total_count)

    unique_asns = dict()

    with open(RIPE_probes) as json_file:
        data = json.load(json_file)
        for p in data['objects']:
            if p['status_name'] == "Connected" and p['asn_v4'] != None and p['id'] not in probes_behind_middleboxes:
                if not p['asn_v4'] in unique_asns:
                    unique_asns[p['asn_v4']] = []
                unique_asns[p['asn_v4']].append(p['id'])

        print('Unique ASNs: ' + str((len(unique_asns))))

        total_probes = 0
        probes = []
        for key, value in unique_asns.items():
            # only use first 3 probes for every ASN
            if len(value) > 3:
                value = value[:3]

            total_probes += len(value)
            for probe in value:
                probes.append(probe)

        print('Total probes: ' + str((total_probes)))
        print('Probes per ASN: ' + str(total_probes / (len(unique_asns))))

        probes.sort()
        #print(probes)

        return probes

def schedule_measurements(selected_probes, start, stop):

    is_success = {}
    response = {}
    #number_of_measurements = math.ceil(len(selected_probes)/1000)
    #print("Number of measurements per cycle: ", number_of_measurements)
    measurement_period = stop - start
    print("")
    print("Measurement days: ", measurement_period.days)  
    print("Measurement start, day: ",  start)

    for day in range(measurement_period.days):
        is_success[day] = {}
        response[day] = {}

        # RIPE Beacons are (only reply to pings):
        # VALID: 93.175.146.1
        # INVALID: 93.175.147.1

        # Job´s Beacons are:
        # VALID: https://014c85d2-d8de-405e-be44-85049db3d9ae.rpki-valid-beacon.meerval.net/valid.json
        # INVALID: https://014c85d2-d8de-405e-be44-85049db3d9ae.rpki-invalid-beacon.meerval.net/invalid.json

        # Cloudflares Beacons are:
        # Valid: https://valid.rpki.cloudflare.com/ - IP: 104.16.128.7/20
        # Invalid: https://invalid.rpki.cloudflare.com/ - IP: 103.21.244.14 /24 (only /23 has a ROA with maxlength 23)

        measurement_allocation={
            "147.28.2.1": ["isi", "anchor"],
            "147.28.3.1": ["isi", "experiment"],
            "147.28.4.1": ["gatech", "anchor"],
            "147.28.5.1": ["gatech", "experiment"],

            "147.28.8.1": ["seattle_RS", "anchor"],
            "147.28.9.1": ["seattle_RS", "experiment"],
            "147.28.10.1": ["seattle_wo_RS", "anchor"],
            "147.28.11.1": ["seattle_wo_RS", "experiment"],

            "147.28.12.1": ["amsterdam_RS", "anchor"],
            "147.28.13.1": ["amsterdam_RS", "experiment"],
            "147.28.14.1": ["amsterdam_wo_RS", "anchor"],
            "147.28.15.1": ["amsterdam_wo_RS", "experiment"],

            "45.132.188.1": ["grnet", "anchor"],
            "45.132.189.1": ["grnet", "experiment"],
            "45.132.190.1": ["uw", "anchor"],
            "45.132.191.1": ["uw", "experiment"],

        }

        measurements_http = []
        measurements_traceroute = []

        # HTTP measurement scheduler

        tmp_day = day + 0

        for ip in measurement_allocation.keys():
            mux = measurement_allocation[ip][0]
            rpki_state = measurement_allocation[ip][1]

            #We need to use the same naming valid/invalid as Job uses this
            if rpki_state == "anchor":
                validity = "valid"
            elif rpki_state == "experiment":
                validity = "invalid"

            if ip == "93.175.146.1" or ip == "93.175.147.1": continue #HTTP not possible for RIPE Beacons

            measurements_http.append( Http(
                af=4,
                target=ip,
                description= mux + " RPKI " + rpki_state + " HTTP beacon test - measurement day" + str(tmp_day),
                protocol="HTTP",
                resolve_on_probe="yes",
                path="/"+validity+".json",
                method="GET",
                port=80,
            ))



        # Traceroute measurement scheduler

        for ip in measurement_allocation.keys():
            mux = measurement_allocation[ip][0]
            rpki_state = measurement_allocation[ip][1]

            measurements_traceroute.append( Traceroute(
                af=4,
                target=ip,
                description= mux + " RPKI " + rpki_state + " ICMP beacon test - measurement day" + str(tmp_day),
                protocol="ICMP",
                resolve_on_probe="yes",
                paris=16,
            ))


        #value = [34260]
        value = ','.join([str(x) for x in selected_probes])
        #print(value)
        source = AtlasSource(type="probes", value=value, requested=len(selected_probes))
        #[value.append(str(x)) for x in selected_probes]
        #source = AtlasSource(type="probes", value=value, requested=len(value))


        # HTTP to Account Nils

        atlas_request = AtlasCreateRequest(
            start_time=start,
            key=ATLAS_API_KEY,
            measurements=measurements_http,
            sources=[source],
            is_oneoff=True
        )

        (is_success[day]["http"], response[day]["http"]) = atlas_request.create()


        # Traceroutes to Account Nils
        delayed_start = start + datetime.timedelta(minutes=5)

        atlas_request = AtlasCreateRequest(
            start_time=delayed_start,
            key=ATLAS_API_KEY,
            measurements=measurements_traceroute,
            sources=[source],
            is_oneoff=True
        )

        (is_success[day]["traceroute"], response[day]["traceroute"]) = atlas_request.create()


        # Next day
        start += datetime.timedelta(days=1)


    return is_success, response


def create_folders(start, stop, folder_prefix):
    date = datetime.datetime.strftime(start, '%Y%m%d')
    print(date)
    path = folder_prefix + "/" + date + "/"
    if not os.path.exists(path):
        os.makedirs(path + "traceroute")
        os.makedirs(path + "http")

    #Next day
    date = datetime.datetime.strftime(start + datetime.timedelta(days=1), '%Y%m%d')
    path = folder_prefix + "/" + date + "/"
    print(date)
    if not os.path.exists(path):
        os.makedirs(path + "traceroute")
        os.makedirs(path + "http")


def read_middlebox_file(filename):
    probes_behind_middleboxes = set()
    with open(filename) as f:
        [probes_behind_middleboxes.add(int(line.rstrip('\n'))) for line in f]
    return probes_behind_middleboxes


def save_ids_to_files(response, start, stop, folder_prefix):
    date = datetime.datetime.strftime(start, '%Y%m%d')
    #print(date)
    path = folder_prefix + "/" + date + "/"

    with open(path + "traceroute/measurement_ids.json", "w") as write_file:
        write_file.write(json.dumps(response[0]["traceroute"]["measurements"]))
    with open(path + "http/measurement_ids.json", "w") as write_file:
        write_file.write(json.dumps(response[0]["http"]["measurements"]))

    date = datetime.datetime.strftime(start + datetime.timedelta(days=1), '%Y%m%d')
    #print(date)
    path = folder_prefix + "/" + date + "/"

    with open(path + "traceroute/measurement_ids.json", "w") as write_file:
        write_file.write(json.dumps(response[1]["traceroute"]["measurements"]))
    with open(path + "http/measurement_ids.json", "w") as write_file:
        write_file.write(json.dumps(response[1]["http"]["measurements"]))


def main(args):

    args = parse_arguments(args)

    folder_prefix = "Atlas/annet"
    RIPE_probes = args.input
    print("Input file: ", RIPE_probes)

    probes_behind_middleboxes = read_middlebox_file("Atlas/middlebox/middleboxes_probe_ids_20210626.txt")
    print("Middlebox file: ", probes_behind_middleboxes)

    selected_probes = probe_selection(RIPE_probes, probes_behind_middleboxes)
    print("Selected probes: ")
    print(selected_probes)
    print("")

    for i in probes_behind_middleboxes:
        if i in selected_probes:
            print('Found Middlebox probe: ', i)

    #ROAs flip at 00:30 UTC, therefore we start the experiment 15min earlier to catch the last state


    #The scheduler seems to be off by one day / it does not schedule the last day!
    # We schedule 1 day in advance, e.g. on 27th for 29th and 30th
    now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    start = datetime.datetime(now.year, now.month, now.day, 0, 5, 0)
    #start = datetime.datetime(2020, 5, 27, 0, 15, 0) #Manual overwrite
    now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3)
    stop = datetime.datetime(now.year, now.month, now.day, 0, 5, 0)
    #stop = datetime.datetime(2020, 5, 29, 0, 15, 0) #Manual overwrite

    #print(start, stop)

    create_folders(start, stop, folder_prefix) #Creates traceroute and http folders

    #Return valiables are dicts
    is_success, response = schedule_measurements(selected_probes, start, stop)
    print(response)
    save_ids_to_files(response, start, stop, folder_prefix)


    for day in range(len(is_success)):
        print("")
        print("Day: ", day)

        if is_success[day]["http"] == False: print('Something went wrong - HTTP Measurement not scheduled! ' + str(response[day]["http"]))
        else: print('Measurement ' + str(response[day]["http"])  + 'successfully scheduled!')
        print("")

        if is_success[day]["traceroute"] == False: print('Something went wrong - Traceroute Measurement not scheduled! ' + str(response[day]["traceroute"]))
        else: print('Measurement ' + str(response[day]["traceroute"])  + 'successfully scheduled!')
        print("")

    #pickle.dump(response, open(folder_prefix + "/ids.pickle", "wb"))



    print("")
    print("Only Measurement IDs: ")
    for day in range(len(is_success)):
        print("Day: ", day)
        print("")
        print(response[day]["http"]["measurements"])
        print("")
        print(response[day]["traceroute"]["measurements"])


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))