import sys
from filter_packets import *
from packet_parser import *
from compute_metrics import *


def metrics_out(node, data_metrics, time_metrics):
    out_filename = node + '_metrics.csv'
    out_file = open(out_filename, 'w')

    metrics_all = [node]
    metrics_all.extend(data_metrics)
    metrics_all.extend(time_metrics)

    metrics = "{}\n\nEcho Requests Sent,Echo Requests Received,Echo Replies Sent,Echo Replies Recieved\n{},{},{}," \
              "{}\nEcho Request Bytes Sent (bytes),Echo Request Data Sent (bytes)\n{},{}\nEcho Request Bytes Received " \
              "(bytes),Echo Request Data Received (bytes)\n{},{}\n\nAverage RTT (milliseconds),{}\nEcho Request " \
              "Throughput (kB/sec),{}\nEcho Request Goodput (kB/sec),{}\n".format(
        *metrics_all)

    out_file.write(metrics)
    out_file.close()


if len(sys.argv) < 2:
    print("{}: invalid amount of arguments".format(sys.argv[1]))
    sys.exit(1)
else:
    for node in sys.argv[1:]:
        filter(node)
        node_split = node.split('.')
        node_join = '_filtered.'.join(node_split)
        fields_list = parse(node_join)
        data_size_metrics, time_based_metrics = \
            compute(node_split[0], fields_list)
        metrics_out(node_split[0], data_size_metrics, time_based_metrics)
