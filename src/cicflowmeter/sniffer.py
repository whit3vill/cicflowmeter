import argparse
import pandas as pd
import numpy as np

from scapy.sendrecv import AsyncSniffer

from .flow_session import generate_session_class


def create_sniffer(
    input_file, input_interface, output_mode, output_file, url_model=None
):
    assert (input_file is None) ^ (input_interface is None)

    NewFlowSession = generate_session_class(output_mode, output_file, url_model)

    if input_file is not None:
        return AsyncSniffer(
            offline=input_file,
            filter="ip and (tcp or udp)",
            prn=None,
            session=NewFlowSession,
            store=False,
        )
    else:
        return AsyncSniffer(
            iface=input_interface,
            filter="ip and (tcp or udp)",
            prn=None,
            session=NewFlowSession,
            store=False,
        )


def main():
    parser = argparse.ArgumentParser()

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-i",
        "--interface",
        action="store",
        dest="input_interface",
        help="capture online data from INPUT_INTERFACE",
    )

    input_group.add_argument(
        "-f",
        "--file",
        action="store",
        dest="input_file",
        help="capture offline data from INPUT_FILE",
    )

    output_group = parser.add_mutually_exclusive_group(required=False)
    output_group.add_argument(
        "-c",
        "--csv",
        "--flow",
        action="store_const",
        const="flow",
        dest="output_mode",
        help="output flows as csv",
    )

    url_model = parser.add_mutually_exclusive_group(required=False)
    url_model.add_argument(
        "-u",
        "--url",
        action="store",
        dest="url_model",
        help="URL endpoint for send to Machine Learning Model. e.g http://0.0.0.0:80/prediction",
    )

    parser.add_argument(
        "output",
        help="output file name (in flow mode) or directory (in sequence mode)",
    )

    parser.add_argument(
        "-o",
        "--outputcsv",
        type=str,
        dest="output_csv",
        required=False,
        help="output csv for Machine Learning Model.",
    )

    args = parser.parse_args()

    sniffer = create_sniffer(
        args.input_file,
        args.input_interface,
        args.output_mode,
        args.output,
        args.url_model,
    )
    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        sniffer.join()
    
    if args.output_csv is not None:
        df= pd.read_csv(args.output)
        
        ef = df[['dst_port','flow_duration','tot_fwd_pkts','tot_bwd_pkts','totlen_fwd_pkts','totlen_bwd_pkts','fwd_pkt_len_max','fwd_pkt_len_min','fwd_pkt_len_mean','fwd_pkt_len_std','bwd_pkt_len_max','bwd_pkt_len_min','bwd_pkt_len_mean','bwd_pkt_len_std','flow_byts_s','flow_pkts_s','flow_iat_mean','flow_iat_std','flow_iat_max','flow_iat_min','fwd_iat_tot','fwd_iat_mean','fwd_iat_std','fwd_iat_max','fwd_iat_min','bwd_iat_tot','bwd_iat_mean','bwd_iat_std','bwd_iat_max','bwd_iat_min','fwd_psh_flags','bwd_psh_flags','fwd_urg_flags','bwd_urg_flags','fwd_header_len','bwd_header_len','fwd_pkts_s','bwd_pkts_s','pkt_len_min','pkt_len_max','pkt_len_mean','pkt_len_std','pkt_len_var','fin_flag_cnt','syn_flag_cnt','rst_flag_cnt','psh_flag_cnt','ack_flag_cnt','urg_flag_cnt','cwe_flag_count','ece_flag_cnt','down_up_ratio','pkt_size_avg','fwd_seg_size_avg','bwd_seg_size_avg','fwd_header_len','fwd_byts_b_avg','fwd_pkts_b_avg','fwd_blk_rate_avg','bwd_byts_b_avg','bwd_pkts_b_avg','bwd_blk_rate_avg','subflow_fwd_pkts','subflow_fwd_byts','subflow_bwd_pkts','subflow_bwd_byts','init_fwd_win_byts','init_bwd_win_byts','fwd_act_data_pkts','fwd_seg_size_min','active_mean','active_std','active_max','active_min','idle_mean','idle_std','idle_max','idle_min']]
        ef.to_csv("model_input_data.csv", index=False, header=False)
        ff = df[['src_ip','src_port','dst_ip','dst_port','protocol','timestamp','flow_duration','tot_fwd_pkts','tot_bwd_pkts','totlen_fwd_pkts','totlen_bwd_pkts','fwd_pkt_len_max','fwd_pkt_len_min','fwd_pkt_len_mean','fwd_pkt_len_std','bwd_pkt_len_max','bwd_pkt_len_min','bwd_pkt_len_mean','bwd_pkt_len_std','flow_byts_s','flow_pkts_s','flow_iat_mean','flow_iat_std','flow_iat_max','flow_iat_min','fwd_iat_tot','fwd_iat_mean','fwd_iat_std','fwd_iat_max','fwd_iat_min','bwd_iat_tot','bwd_iat_mean','bwd_iat_std','bwd_iat_max','bwd_iat_min','fwd_psh_flags','bwd_psh_flags','fwd_urg_flags','bwd_urg_flags','fwd_header_len','bwd_header_len','fwd_pkts_s','bwd_pkts_s','pkt_len_min','pkt_len_max','pkt_len_mean','pkt_len_std','pkt_len_var','fin_flag_cnt','syn_flag_cnt','rst_flag_cnt','psh_flag_cnt','ack_flag_cnt','urg_flag_cnt','cwe_flag_count','ece_flag_cnt','down_up_ratio','pkt_size_avg','fwd_seg_size_avg','bwd_seg_size_avg','fwd_header_len','fwd_byts_b_avg','fwd_pkts_b_avg','fwd_blk_rate_avg','bwd_byts_b_avg','bwd_pkts_b_avg','bwd_blk_rate_avg','subflow_fwd_pkts','subflow_fwd_byts','subflow_bwd_pkts','subflow_bwd_byts','init_fwd_win_byts','init_bwd_win_byts','fwd_act_data_pkts','fwd_seg_size_min','active_mean','active_std','active_max','active_min','idle_mean','idle_std','idle_max','idle_min']]
        header = ['Source IP','Source Port','Destination IP','Destination Port','Protocol','Timestamp','Flow Duration','Total Fwd Packets','Total Backward Packets','Total Length of Fwd Packets','Total Length of Bwd Packets','Fwd Packet Length Max','Fwd Packet Length Min','Fwd Packet Length Mean','Fwd Packet Length Std','Bwd Packet Length Max','Bwd Packet Length Min','Bwd Packet Length Mean','Bwd Packet Length Std','Flow Bytes/s','Flow Packets/s','Flow IAT Mean','Flow IAT Std','Flow IAT Max','Flow IAT Min','Fwd IAT Total','Fwd IAT Mean','Fwd IAT Std','Fwd IAT Max','Fwd IAT Min','Bwd IAT Total','Bwd IAT Mean','Bwd IAT Std','Bwd IAT Max','Bwd IAT Min','Fwd PSH Flags','Bwd PSH Flags','Fwd URG Flags','Bwd URG Flags','Fwd Header Length','Bwd Header Length','Fwd Packets/s','Bwd Packets/s','Min Packet Length','Max Packet Length','Packet Length Mean','Packet Length Std','Packet Length Variance','FIN Flag Count','SYN Flag Count','RST Flag Count','PSH Flag Count','ACK Flag Count','URG Flag Count','CWE Flag Count','ECE Flag Count','Down/Up Ratio','Average Packet Size','Avg Fwd Segment Size','Avg Bwd Segment Size','Fwd Header Length.1','Fwd Avg Bytes/Bulk','Fwd Avg Packets/Bulk','Fwd Avg Bulk Rate','Bwd Avg Bytes/Bulk','Bwd Avg Packets/Bulk','Bwd Avg Bulk Rate','Subflow Fwd Packets','Subflow Fwd Bytes','Subflow Bwd Packets','Subflow Bwd Bytes','Init_Win_bytes_forward','Init_Win_bytes_backward','act_data_pkt_fwd','min_seg_size_forward','Active Mean','Active Std','Active Max','Active Min','Idle Mean','Idle Std','Idle Max','Idle Min']
        ff.columns = header
        ff.insert(0, 'Flow ID', 'testlog')
        ff.to_csv("to_elastic.csv")
        


if __name__ == "__main__":
    main()
