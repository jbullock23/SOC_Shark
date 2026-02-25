#!/usr/bin/env python3
### SOC_Shark.py
##
##
##
# ===== IMPORTS =====
import sys, os, ipaddress, hashlib
from datetime import datetime
from scapy.all import *
from scapy.utils import PcapReader
import pandas as pd
import geoip2.database

# Configure this section based on your network
# GEOIP_DB will need the corresponding file in the same directory as the SOC Parser.py
# Not having GeoLite file configured will not impact the script. 
# ===== CONFIG =====
INTERNAL_NETWORK = "192.168.0.0/16"
GEOIP_DB = "GeoLite2-Country.mmdb"

# ===== INPUT VALIDATION =====
if len(sys.argv) < 2:
    print("Usage: python pcap_parser.py <file.pcap|pcapng>")
    sys.exit(1)

PCAP_FILE = sys.argv[1]
if not os.path.exists(PCAP_FILE):
    print("File not found")
    sys.exit(1)

internal_net = ipaddress.ip_network(INTERNAL_NETWORK)

# ===== PROTOCOL MAP =====
PROTO_MAP = {
    1:"ICMP",2:"IGMP",6:"TCP",17:"UDP",
    47:"GRE",50:"ESP",51:"AH",89:"OSPF"
}

# ===== GEOIP =====
geo_reader = None
if os.path.exists(GEOIP_DB):
    geo_reader = geoip2.database.Reader(GEOIP_DB)

def geo_lookup(ip):
    try:
        if geo_reader and ip:
            return geo_reader.country(ip).country.iso_code
    except:
        pass
    return "NA"


## Connection classification uses TCP flags:
#	Flags 			Meaning
#	SYN(S)		Connection attempt
# 	SYN-ACK(SA)	Successful handshake
# 	RST(R)		Failed connection 
# ===== HELPERS =====
def connection_status(flags):
    if flags == "S": return "attempt"
    if flags == "SA": return "success"
    if flags == "R": return "failed"
    return "other"

def direction(src_ip, dst_ip):
    try:
        src_int = ipaddress.ip_address(src_ip) in internal_net
        dst_int = ipaddress.ip_address(dst_ip) in internal_net
        if src_int and not dst_int: return "outbound"
        if not src_int and dst_int: return "inbound"
        if src_int and dst_int: return "internal"
    except:
        pass
    return "external"

def flow_hash(src, dst, sport, dport, proto):
    return hashlib.md5(f"{src}{dst}{sport}{dport}{proto}".encode()).hexdigest()


# The HTTP Parser won't be a huge component in this script, I thought it was a cool add in for new learners, and could be a # nice lesson for those using login credentials via HTTP.  
# Detects: HTTP methods, Host header, URI, Cookies, User-Agent, POST body, and Potential credentials
# ===== HTTP PARSER =====
def parse_http_payload(payload):
    http_method=http_host=http_uri=http_user_agent=http_cookie=http_body=http_credentials=None
    try:
        text = payload.decode(errors="ignore")

        if text.startswith(("GET","POST","PUT","DELETE","HEAD","OPTIONS")):
            lines = text.split("\r\n")
            first_line = lines[0].split()

            if len(first_line)>=2:
                http_method = first_line[0]
                http_uri = first_line[1]

            for line in lines:
                if line.lower().startswith("host:"):
                    http_host=line.split(":",1)[1].strip()
                if line.lower().startswith("user-agent:"):
                    http_user_agent=line.split(":",1)[1].strip()
                if line.lower().startswith("cookie:"):
                    http_cookie=line.split(":",1)[1].strip()

            if "\r\n\r\n" in text:
                http_body=text.split("\r\n\r\n",1)[1]

            cred_keywords=["username","user","login","email","password","pass","pwd"]
            if http_body and any(k+"=" in http_body.lower() for k in cred_keywords):
                http_credentials=http_body

    except:
        pass

    return http_method,http_host,http_uri,http_user_agent,http_cookie,http_body,http_credentials

# Detect IPs, Ports, Protocols,DNS Query, and optional GEOIP 
# ===== PARSE PCAP =====
records = []
packets = PcapReader(PCAP_FILE)

for pkt in packets:
    try:
        src_ip=dst_ip=src_mac=dst_mac=src_port=dst_port=tcp_flags=dns_query=None
        proto_name=None
        conn_status="other"

        http_method=http_host=http_uri=http_user_agent=http_cookie=http_body=http_credentials=None

        timestamp = datetime.fromtimestamp(float(pkt.time)).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        packet_size = len(pkt)

        if Ether in pkt:
            src_mac=pkt[Ether].src
            dst_mac=pkt[Ether].dst

        if IP in pkt:
            src_ip=pkt[IP].src
            dst_ip=pkt[IP].dst
            proto_name=PROTO_MAP.get(pkt[IP].proto, str(pkt[IP].proto))

        if TCP in pkt:
            src_port=pkt[TCP].sport
            dst_port=pkt[TCP].dport
            tcp_flags=str(pkt[TCP].flags)
            conn_status=connection_status(tcp_flags)

            if Raw in pkt and (pkt[TCP].dport==80 or pkt[TCP].sport==80):
                http_method,http_host,http_uri,http_user_agent,http_cookie,http_body,http_credentials = parse_http_payload(bytes(pkt[Raw]))

        elif UDP in pkt:
            src_port=pkt[UDP].sport
            dst_port=pkt[UDP].dport
            conn_status="udp"

        if DNS in pkt and pkt[DNS].qd:
            dns_query=pkt[DNSQR].qname.decode(errors="ignore")

        geo=geo_lookup(dst_ip)
        dirn=direction(src_ip,dst_ip) if src_ip and dst_ip else "unknown"
        flow=flow_hash(src_ip,dst_ip,src_port,dst_port,proto_name)

# How captured info is displayed in the CSV

        row={
            "timestamp":timestamp,
            "src_ip":src_ip,
            "dst_ip":dst_ip,
            "src_mac":src_mac,
            "dst_mac":dst_mac,
            "src_port":src_port,
            "dst_port":dst_port,
            "protocol":proto_name,
            "tcp_flags":tcp_flags,
            "packet_size":packet_size,
            "dns_query":dns_query,
            "connection_status":conn_status,
            "direction":dirn,
            "flow_id":flow,
            "geoip_country":geo,
            "http_method":http_method,
            "http_host":http_host,
            "http_uri":http_uri,
            "http_user_agent":http_user_agent,
            "http_cookie":http_cookie,
            "http_body":http_body,
            "http_credentials":http_credentials
        }

        records.append(row)

    except:
        continue
        
#Added cleanup to allow for a smoother visual in the CSV file.
# ===== CLEANUP =====
df=pd.DataFrame(records)

df=df.dropna(how="all", subset=[
    "src_ip","dst_ip","src_port","dst_port","protocol","tcp_flags"
])

df=df.drop_duplicates()

# ===== EXPORT =====
output=os.path.splitext(PCAP_FILE)[0]+"_analysis.csv"
df.to_csv(output,index=False)

print(f"CSV exported: {output}")
