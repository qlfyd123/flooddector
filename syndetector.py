import configparser

from scapy.all import *
from scapy.layers.inet import TCP, IP


def get_syn_conn_status():
    def packet_callback(packet):
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            # with open('syn_packets_log.txt', 'a') as file:
            #     file.write(f'{packet[IP].src} is sending a SYN packet to {packet[IP].dst}\n')
            return True
        return False

    packets = sniff(filter="tcp", store=1, timeout=SleepTime)
    syn_packet_count = sum(1 for packet in packets if packet_callback(packet))
    return syn_packet_count


def adjust_backlog_limit(index, increase):
    if increase:
        adjusted_backlog = BacklogLimit[index]
        action = 'increase'
    else:
        adjusted_backlog = BacklogLimit[index]
        action = 'decrease'

    with open('/proc/sys/net/ipv4/tcp_max_syn_backlog', 'w') as file:
        file.write(str(adjusted_backlog))

    now = datetime.now()
    with open('server_change_log.txt', 'a') as log_file:
        log_file.write(f'{action} backlog to {adjusted_backlog} at {now}\n')


def get_synack_retries_status():
    with open('/proc/sys/net/ipv4/tcp_synack_retries', 'r') as file:
        return int(file.read().strip())


def adjust_synack_retries(increase):
    synack_retries = get_synack_retries_status()
    action = 'increase' if increase else 'decrease'

    if increase:
        synack_retries += 1
    else:
        synack_retries -= 1

    with open('/proc/sys/net/ipv4/tcp_synack_retries', 'w') as file:
        file.write(str(synack_retries))

    now = datetime.now()
    with open('server_change_log.txt', 'a') as log_file:
        log_file.write(f'{action} synack_retries to {synack_retries} at {now}\n')


def get_syn_cookie_status():
    with open('/proc/sys/net/ipv4/tcp_syncookies', 'r') as file:
        return int(file.read().strip())


def adjust_syncookies(enable):
    syncookies_status = '1' if enable else '0'
    action = 'enable' if enable else 'disable'

    with open('/proc/sys/net/ipv4/tcp_syncookies', 'w') as file:
        file.write(syncookies_status)

    now = datetime.now()
    with open('server_change_log.txt', 'a') as log_file:
        log_file.write(f'{action} syncookies at {now}\n')


def detect_packet(index):
    conn_count = get_syn_conn_status()
    print(f'Connection count: {conn_count}')
    if conn_count >= BacklogLimit[index]:
        if index < len(BacklogLimit) - 1:
            index += 1
            adjust_backlog_limit(index, True)
        else:
            if get_synack_retries_status() != 1:
                adjust_synack_retries(False)
            else:
                if get_syn_cookie_status() == 0:
                    adjust_syncookies(True)
    else:
        if get_syn_cookie_status() == 1:
            adjust_syncookies(False)
        else:
            if get_synack_retries_status() != SYNACKretries:
                adjust_synack_retries(True)
            else:
                if index > 0:
                    index -= 1
                    adjust_backlog_limit(index, False)
    return index


config = configparser.ConfigParser()
config.read('config.ini')
BacklogLimit = [int(x) for x in config['DEFAULT']['packetLimitArray'].split(',')]
SleepTime = int(config['DEFAULT']['SleepTime'])
SYNACKretries = int(config['DEFAULT']['SynAckRetries'])
index = 0
while True:
    index = detect_packet(index)
