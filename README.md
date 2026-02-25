# SOC_Shark

Overview
This script is a lightweight SOC investigation tool designed to parse PCAP and PCAPNG network captures 
and export meaningful metadata into a structured CSV file.

Requirements
Install dependencies:
pip install scapy pandas geoip2
  Optional: geoip2
    Create an account and download GeoLite2 country database from MaxMind and 
    place it in the same directory as the script 

Usage
python SOC_Shark.py capture.pcap
 Output:
capture_analysis.csv

Analyst Notes
This tool is best used as a triage accelerator, not a replacement for deep packet inspection tools.

Recommended workflow:
Run parser
Sort CSV by risk indicators (ports, direction, flags)
Investigate suspicious flows in Wireshark
Pivot into SIEM or threat intel platforms

Disclaimer
This script is intended for home-lab, and learning use. If you wish to use in a Enterprise or SOC environment, 
please keep in mind this not a replacement tool Wireshark. It is to be used in conjunction with programs like 
Wireshark, and other SIEM tools.
