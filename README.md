# TMA-21
This repository holds artifacts from the TMA2021 paper: Revisiting RPKI Route Origin Validation on the Data Plane


code
  - schedule_measurements.py: RIPE Atlas measurement scheduler script using the RIPE Atlas API.
  - Atlas_rov_identification.py: The script that runs the ROV identifications for each measurement day.
  - ip_to_asn.py: The IP->ASN mapper used by Atlas_rov_identification.py
  - pyasn_bulk_converter.sh: A shell script to download RIB files daily and convert them to pyasn database format
  - pyasn_converter.py: A script converting a single RIB to a database file for pyasn
  - pyasn_downloader.py: Modified PyASN downloader script
  - RPKI Data-Plane Results - July 2021 Measurements.ipynb: Jupyter Notebook reading the result files and printing the result values.

data
  - 20201208_PEERING_peers.json: PEERING testbed peer list from 12/08/2021
  - XXX_resultset_asns.json: Result files for 5 specific measurement runs
  - Atlas_probes_info_20210626.json: RIPE Atlas probes information file (meta data)
  - middleboxes_probe_ids_20210626.txt: List of RIPE Atlas probes sitting behind middleboxes (From TAURIN'21 paper)
