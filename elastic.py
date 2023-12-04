import glob
import os
import argparse
import json
import logging
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import streaming_bulk

LOG_FORMATTER = logging.Formatter(fmt="%(asctime)s :: %(levelname)s :: %(message)s", datefmt="%H:%M:%S")
LOGGER = logging.getLogger(__name__)

# Reading in the csv files
folder = "./data/"
os.chdir(Path(folder))
li = []

for file in glob.glob("*.csv"):
    df = pd.read_csv(filepath_or_buffer=file, header=0, sep=",", engine="python")
    
    header = []
    for col in df.columns:
        header.append(col.lstrip())
    df.columns = header

    if "Monday" in file:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M:%S")
    else:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="%d/%m/%Y %H:%M")

    li.append(df)
if not li:
    exit(1)
df = pd.concat(li, axis=0, ignore_index=True)
li = []

df.replace([np.inf, -np.inf], np.nan, inplace=True)
# Drop rows with all values NaN
df.dropna(how="all", inplace=True)
# Fill NaN values with a 0
df.fillna(0, inplace=True)
# Replace empty and whitespace values with a 0
df.replace(["", " "], 0, inplace=True)

df = df.head(5)
print(list(df.columns))
# Connect to Elasticsearch
es = Elasticsearch(
    "https://531f0c9ddb2a44989cabfd8dad39d760.us-central1.gcp.cloud.es.io:443",
    api_key="bUp6aE00d0I3dGpma1RMSlpjWlo6Y0Vnd3NSMXlSMHUtTWdVTFBRZVFBUQ=="
)

# Index the JSON data
index_name = "cicids2017"
doc_type = "flow"

for index, row in df.iterrows():
    body = {
        "@timestamp": row["Timestamp"].strftime('%Y-%m-%dT%H:%M:%S'),
        "@version": "1",
        "ecs": {
            "version": "1.5.0"
        },
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
        "CICFlowMeter": {
            "flow_id": row["Flow ID"],
            "down_up_ratio": row["Down/Up Ratio"],
            "fwd": {
                "psh_flags": row["Fwd PSH Flags"],
                "urg_flags": row["Fwd URG Flags"],
                "header_bytes": row["Fwd Header Length"],
                "header_length": row["Fwd Header Length.1"],
                "packets/s": row["Fwd Packets/s"],
                "init_win_bytes": row["Init_Win_bytes_forward"],
                "act_data_pkt": row["act_data_pkt_fwd"],
                "min_segment_size": row["min_seg_size_forward"],
                "packet_length": {
                    "max": row["Fwd Packet Length Max"],
                    "min": row["Fwd Packet Length Min"],
                    "mean": row["Fwd Packet Length Mean"],
                    "std": row["Fwd Packet Length Std"]
                },
                "IAT": {
                    "total": row["Fwd IAT Total"],
                    "max": row["Fwd IAT Max"],
                    "min": row["Fwd IAT Min"],
                    "mean": row["Fwd IAT Mean"],
                    "std": row["Fwd IAT Std"]
                },
                "avg": {
                    "segment_size": row["Avg Fwd Segment Size"],
                    "bytes/bulk": row["Fwd Avg Bytes/Bulk"],
                    "packets/bulk": row["Fwd Avg Packets/Bulk"],
                    "bulk_rate": row["Fwd Avg Bulk Rate"],
                },
                "subflow": {
                    "packets": row["Subflow Fwd Packets"],
                    "bytes": row["Subflow Fwd Bytes"],
                }
            },
            "bwd": {
                "psh_flags": row["Bwd PSH Flags"],
                "urg_flags": row["Bwd URG Flags"],
                "header_bytes": row["Bwd Header Length"],
                "packets/s": row["Bwd Packets/s"],
                "init_win_bytes": row["Init_Win_bytes_backward"],
                "packet_length": {
                    "max": row["Bwd Packet Length Max"],
                    "min": row["Bwd Packet Length Min"],
                    "mean": row["Bwd Packet Length Mean"],
                    "std": row["Bwd Packet Length Std"]
                },
                "IAT": {
                    "total": row["Bwd IAT Total"],
                    "max": row["Bwd IAT Max"],
                    "min": row["Bwd IAT Min"],
                    "mean": row["Bwd IAT Mean"],
                    "std": row["Bwd IAT Std"]
                },
                "avg": {
                    "segment_size": row["Avg Bwd Segment Size"],
                    "bytes/bulk": row["Bwd Avg Bytes/Bulk"],
                    "packets/bulk": row["Bwd Avg Packets/Bulk"],
                    "bulk_rate": row["Bwd Avg Bulk Rate"],
                },
                "subflow": {
                    "packets": row["Subflow Bwd Packets"],
                    "bytes": row["Subflow Bwd Bytes"],
                }
            },
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
            },
            "active": {
                "max": row["Active Max"],
                "min": row["Active Min"],
                "mean": row["Active Mean"],
                "std": row["Active Std"],
            },
            "idle": {
                "max": row["Idle Max"],
                "min": row["Idle Min"],
                "mean": row["Idle Mean"],
                "std": row["Idle Std"],
            }
        },
        "tags": ["CICIDS2017", row["Label"]],
        "type": "flow"
    }

    json_data = json.dumps(body)
    print(json_data)
