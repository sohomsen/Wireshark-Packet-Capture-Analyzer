import re
from collections import Counter


def _hex_to_ttl(hex_str):
    return str(int(hex_str, 16))


def _hex_to_ip(hex_str):
    hex_str = hex_str.split(" ")
    for i in range(0, 4):
        hex_str[i] = str(int(hex_str[i], 16))
    hex_join = ".".join(hex_str)
    return hex_join


def _hex_to_ip_len(hex_str):
    return str(int(hex_str, 16))


def _hex_to_icmp_id(hex_str):
    hex_str = hex_str.replace(" ", "")
    return "0x" + hex_str


def _hex_to_icmp_seq_num(hex_str):
    hex_str = hex_str.split(" ")
    be = str(int(hex_str[0] + hex_str[1], 16))
    le = str(int(hex_str[1] + hex_str[0], 16))
    return be + "/" + le


def parse(filename):
    regex1 = r"(?s)\b(?:(?!\n\n).)*?(?:(?!\n\nNo\.).)*"
    regex2 = r"(?s)(?<=\n\d{4}\s{2})([0-9a-f]{2}\s)+"
    fields_list = []

    data = open(filename).read()

    packets = re.finditer(regex1, data, re.MULTILINE)

    seq_nums = []

    for packet in packets:
        if packet.group(0) == '':
            continue
        # Grab attributes from beginning of packet
        number = str(packet.group(0))[89:95].strip()
        time = str(packet.group(0))[96:106]

        # Start hex decoding
        hex_dump = re.finditer(regex2, packet.group(0), re.MULTILINE)
        hex_full = ""
        for hex_line in hex_dump:
            hex_full += hex_line.group(0)
        hex_full = hex_full.strip()

        # Hex attribute parsing
        dest_mac = hex_full[0:18].strip().replace(" ", ":")
        source_mac = hex_full[18:35].strip().replace(" ", ":")
        ttl = _hex_to_ttl(hex_full[66:68])
        source_ip = _hex_to_ip(hex_full[78:89])
        dest_ip = _hex_to_ip(hex_full[90:101])
        ip_total_length = _hex_to_ip_len(hex_full[48:53].replace(" ", ""))
        icmp_message_type = hex_full[102:105]
        icmp_id = _hex_to_icmp_id(hex_full[114:119])
        icmp_seq_num = _hex_to_icmp_seq_num(hex_full[120:125])
        icmp_data = hex_full[126:]
        seq_nums.append(icmp_seq_num)
        fields = [time, ttl, source_ip, dest_ip, ip_total_length, icmp_message_type, icmp_seq_num, icmp_data]
        fields_list.append(fields)

    c_seq_nums = Counter(seq_nums)
    return fields_list
