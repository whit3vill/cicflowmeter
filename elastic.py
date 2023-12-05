import argparse
import json
import logging
import pandas as pd
import numpy as np
import warnings
from tqdm import tqdm
from time import sleep
from pathlib import Path
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import streaming_bulk

warnings.filterwarnings('ignore')

parser = argparse.ArgumentParser(description="Script to import pcap features CSV into elasticsearch.")
"""
parser.add_argument("-e --es_host", dest="es_host", type=str, required=True,
                        help="Address of the Elasticsearch host. Required.")  
parser.add_argument("-a --es_api_key", dest="es_api_key", type=str, required=True,
                        help="API key of the Elasticsearch host. Required.")  
"""
parser.add_argument("-f --file", dest="input_file", type=str, required=True,
                        help="Target file. Required.") 
parser.add_argument("-i --es_index", dest="es_index", type=str, required=True,
                        help="Target index to write into. Required.")  
parser.add_argument("-e --es_host", dest="es_host", type=str, default="https://531f0c9ddb2a44989cabfd8dad39d760.us-central1.gcp.cloud.es.io:443",
                        help="Address of the Elasticsearch host. Required.")  
parser.add_argument("-a --es_api_key", dest="es_api_key", type=str, default="dVE5Yk9vd0J2Sjd6RGlRU3pqYXA6SEx3cEdUNnlUQzJJNTZFcWducDE3Zw==",
                        help="API key of the Elasticsearch host. Required.")  
params = parser.parse_args()  

ES_HOST = params.es_host
ES_API_KEY = params.es_api_key
INDEX_NAME = params.es_index
INPUT_FILE = params.input_file

df = pd.read_csv(filepath_or_buffer=INPUT_FILE, sep=',', header=0, engine='python')
header = []
for col in df.columns:
    header.append(col.lstrip())
df.columns = header

if "Monday" in INPUT_FILE:
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S")
else:
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M")

# Fill inf values with NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)
# Drop rows with all values NaN
df.dropna(how="all", inplace=True)
# Fill NaN values with a 0
df.fillna(0, inplace=True)
# Replace empty and whitespace values with a 0
df.replace(["", " "], 0, inplace=True)

es = Elasticsearch(ES_HOST, api_key=ES_API_KEY, verify_certs=False)

bulk_data = []
for idx, row in tqdm(df.iterrows(), total=df.shape[0]):
    bulk_data.append({
        'index': {
            '_index': INDEX_NAME
        }
    })
    bulk_data.append({
        "@timestamp": row["Timestamp"].strftime('%Y-%m-%dT%H:%M:%S'),
        "@version": "1",
        "event": {
            "kind": "event",
            "dataset": "flow",
            "action": "network_flow",
            "category": "network_traffic",
            "start": row["Timestamp"].strftime('%Y-%m-%dT%H:%M:%S'),
            "duration": row["Flow Duration"] * 1000
        },
        "source": {
            "ip": row["Source IP"],
            "port": row["Source Port"],
            "packets": row["Total Fwd Packets"],
            "bytes": row["Total Length of Fwd Packets"]
        },
        "destination": {
            "ip": row["Destination IP"],
            "port": row["Destination Port"],
            "packets": row["Total Backward Packets"],
            "bytes": row["Total Length of Bwd Packets"]
        },
        "network": {
            "transport": row["Protocol"],
            "type": "ipv4",
            "bytes": row["Total Length of Fwd Packets"] + row["Total Length of Bwd Packets"],
            "packets": row["Total Fwd Packets"] + row["Total Backward Packets"]
        },
        "Flow": {
            "flow_id": row["Flow ID"],
            "down_up_ratio": row["Down/Up Ratio"],
            "flow": {
                "bytes/s": row["Flow Bytes/s"],
                "packets/s": row["Flow Packets/s"],
                "IAT": {
                    "max": row["Flow IAT Max"],
                    "min": row["Flow IAT Min"],
                    "mean": row["Flow IAT Mean"],
                    "std": row["Flow IAT Std"]
                }
            },
            "packets": {
                "avg_size": row["Average Packet Size"],
                "length": {
                    "max": row["Max Packet Length"],
                    "min": row["Min Packet Length"],
                    "mean": row["Packet Length Mean"],
                    "std": row["Packet Length Std"],
                    "variance": row["Packet Length Variance"],
                }
            },
            "flag_count": {
                "FIN": row["FIN Flag Count"],
                "SYN": row["SYN Flag Count"],
                "RST": row["RST Flag Count"],
                "PSH": row["PSH Flag Count"],
                "ACK": row["ACK Flag Count"],
                "URG": row["URG Flag Count"],
                "CWE": row["CWE Flag Count"],
                "ECE": row["ECE Flag Count"],
            }
        },
        "tags": row["Label"],
    })

    if len(bulk_data) >= 1000:
        es.bulk(operations=bulk_data)
        bulk_data = []

if bulk_data:
    es.bulk(operations=bulk_data)
