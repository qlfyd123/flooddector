import time


def get_syncookie_value():
    with open('/proc/sys/net/ipv4/tcp_syncookies', 'r') as file:
        syncookie_value = file.read().strip()
    return syncookie_value


def get_synack_retries():
    with open('/proc/sys/net/ipv4/tcp_synack_retries', 'r') as file:
        synack_retries = file.read().strip()
    return synack_retries


def get_max_syn_backlog():
    with open('/proc/sys/net/ipv4/tcp_max_syn_backlog', 'r') as file:
        max_syn_backlog = file.read().strip()
    return max_syn_backlog


while True:
    syncookie = get_syncookie_value()
    synack_retries = get_synack_retries()
    syn_backlog = get_max_syn_backlog()
    print(f"SYN Cookies: {syncookie}\nSYN ACK Retries: {synack_retries}\nMax SYN Backlog: {syn_backlog} \n"
          f"====================\n")
    time.sleep(5)
