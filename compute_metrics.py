from collections import *


def mean(data):
    n = len(data)
    return sum(data) / float(n)


def _data_size_metrics(NodeIP, fields):
    icmp_type_sent = []
    icmp_type_received = []
    frame_bytes_sent = 0
    frame_bytes_received = 0
    icmp_data_sent = 0
    icmp_data_received = 0
    for field in fields:
        if field[2] == NodeIP:
            icmp_type_sent.append(field[5])
            if field[5] == 8:
                frame_bytes_sent += (field[4] + 14)
                icmp_data_sent += (field[4] - 28)
        else:
            icmp_type_received.append(field[5])
            if field[5] == 8:
                frame_bytes_received += (field[4] + 14)
                icmp_data_received += (field[4] - 28)
        c_icmp_type_sent = Counter(icmp_type_sent)
        c_icmp_type_received = Counter(icmp_type_received)
    # print "Echo Requests Sent: {}".format(c_icmp_type_sent[8])
    # print "Echo Requests Received: {}".format(c_icmp_type_received[8])
    # print "Echo Replies Sent: {}".format(c_icmp_type_sent[0])
    # print "Echo Replies Received: {}".format(c_icmp_type_received[0])
    # print "Echo Request Bytes Sent: {}".format(frame_bytes_sent)
    # print "Echo Request Bytes Received: {}".format(frame_bytes_received)
    # print "Echo Request Data Sent: {}".format(icmp_data_sent)
    # print "Echo Request Data Received: {}".format(icmp_data_received)

    _data_size_metrics.frame_bytes_sent = frame_bytes_sent
    _data_size_metrics.icmp_data_sent = icmp_data_sent

    return [c_icmp_type_sent[8], c_icmp_type_received[8], c_icmp_type_sent[0], \
            c_icmp_type_received[0], frame_bytes_sent, frame_bytes_received, icmp_data_sent, \
            icmp_data_received]


def _time_based_metrics(fields):
    icmp_seq_num_dict = {}
    icmp_requests = []
    icmp_replies = []
    icmp_rtt = []
    for field in fields:
        if field[5] == 8:
            icmp_requests.append(field)
        elif field[5] == 0:
            icmp_replies.append(field)
        else:
            continue
    ### sorts list by seq,src ip,dst ip,time ###
    icmp_requests.sort(key=lambda x: (x[6], x[2], x[3], x[0]))
    ### sorts list by seq,dst ip,src ip,time ###
    icmp_replies.sort(key=lambda x: (x[6], x[3], x[2], x[0]))

    ### iterates through both lists ###
    for request, reply in zip(icmp_requests, icmp_replies):
        ### checks if seq are the same ###
        if request[6] == reply[6] and \
                request[2] == reply[3] and \
                request[3] == reply[2]:
            # indicies = [0,2,3,6]
            # print str(list(request[i] for i in indicies))+'\n'+\
            #      str(list(reply[i] for i in indicies))+'\n\n'

            ### if above is true, then append difference between request and reply 
            icmp_rtt.append(reply[0] - request[0])
            # print icmp_rtt

    #    icmp_seq_num_dict.setdefault(field[6], []).append(field[0])
    # for icmp_seq in icmp_seq_num_dict.iteritems():
    #    #print icmp_seq
    #    icmp_rtt.append(icmp_seq[1][1]-icmp_seq[1][0])

    icmp_rtt_avg = round(mean(icmp_rtt) * 1000, 2)
    # print "Avg. RTT: {}".format(icmp_rtt_avg)
    icmp_rtt_sum = round(sum(icmp_rtt) * 1000, 2)
    # print "Sum of RTT: {}".format(icmp_rtt_sum)

    frame_bytes_sent_kB = (_data_size_metrics.frame_bytes_sent)
    icmp_data_sent_kB = (_data_size_metrics.icmp_data_sent)

    icmp_throughput = round((frame_bytes_sent_kB / icmp_rtt_sum), 1)
    # print "ICMP Throughput in KB/s: {}".format(icmp_throughput)

    icmp_goodput = round((icmp_data_sent_kB / icmp_rtt_sum), 1)
    # print "ICMP Goodput in KB/s: {}".format(icmp_goodput)

    return [icmp_rtt_avg, icmp_throughput, icmp_goodput]


def compute(node, fields):
    print("Working on {}".format(node))
    seq_nums = []
    ### Convert field values from strings to native types ###
    for field in fields:
        field[0] = float(field[0])  # Time diff in microseconds
        field[1] = int(field[1])  # TTL
        # field[2] Source IP
        # field[3] Dest IP
        field[4] = int(field[4])  # IP Total Length
        field[5] = int(field[5])  # ICMP Type
        field[6] = int(field[6].split('/')[0])  # Sequence number
        field[7] = int((len(field[7].strip()) + 1) / 3)  # ICMP Data Len
        seq_nums.append(field[6])

    c_seq_nums = Counter(seq_nums)
    # print len(seq_nums)
    # print c_seq_nums
    ### Change Node IP ###
    if node == "Node1":
        NodeIP = "192.168.100.1"
    elif node == "Node2":
        NodeIP = "192.168.100.2"
    elif node == "Node3":
        NodeIP = "192.168.200.1"
    elif node == "Node4":
        NodeIP = "192.168.200.2"
    else:
        NodeIP = ''

    ### Compute Metrics ###
    data_size_metrics = _data_size_metrics(NodeIP, fields)
    time_based_metrics = _time_based_metrics(fields)

    return (data_size_metrics, time_based_metrics)
