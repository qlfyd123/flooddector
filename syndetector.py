import configparser

from scapy.all import *
from scapy.layers.inet import TCP, IP


def get_syn_conn_status() -> int:
    """
    이 함수는 SYN 패킷을 감지하고 SYN 패킷의 개수를 반환합니다.
    :return: SYN 패킷의 개수
    """

    def packet_callback(packet: Packet) -> bool:
        """
        이 함수는 SYN 패킷을 감지하고, 현재 날짜에 맞게 SYN패킷을 PCAP 파일로 저장합니다.
        :param packet: 감지된 SYN 패킷
        :return: SYN PACKET 이면 True, 아니면 False 반환
        """
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            # pkt = PcapWriter(filedir + str(today.day) + ".pcap", append=True, sync=True)
            # pkt.write(packet)
            return True
        return False

    packets = sniff(filter="tcp", store=1, timeout=SLEEPTIME)
    syn_packet_count = sum(1 for packet in packets if packet_callback(packet))
    return syn_packet_count


def adjust_backlog_limit(index: int, increase: bool) -> None:
    """
    이 함수는 백로그 크기를 조정합니다.
    :param index: 백로그 크기를 조정할 인덱스
    :param increase: Ture면 백로그 증가, False면 감소
    """
    if increase:
        adjusted_backlog = BACKLOG_LIMIT_ARRAY[index]
        action = 'increase'
    else:
        adjusted_backlog = BACKLOG_LIMIT_ARRAY[index]
        action = 'decrease'

    with open('/proc/sys/net/ipv4/tcp_max_syn_backlog', 'w') as file:
        file.write(str(adjusted_backlog))

    now = datetime.now()
    with open('server_change_log.txt', 'a') as log_file:
        log_file.write(f'{action} backlog to {adjusted_backlog} at {now}\n')


def get_synack_retries_status() -> int:
    """
    이 함수는 SYNACK 재시도 횟수를 반환합니다.
    :return: SYNACK 재시도 횟수
    """
    with open('/proc/sys/net/ipv4/tcp_synack_retries', 'r') as file:
        return int(file.read().strip())


def adjust_synack_retries(increase: bool) -> None:
    """
    이 함수는 SYNACK 재시도 횟수를 조정합니다.
    :param increase: true면 SYNACK 재시도 횟수 증가, false면 감소
    """
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


def get_syn_cookie_status() -> int:
    """
    :return: SYN 쿠키 상태
    """
    with open('/proc/sys/net/ipv4/tcp_syncookies', 'r') as file:
        return int(file.read().strip())


def adjust_syncookies(enable: bool) -> None:
    """
    :param enable: true면 SYN 쿠키 활성화, false면 비활성화
    """
    syncookies_status = '1' if enable else '0'
    action = 'enable' if enable else 'disable'

    with open('/proc/sys/net/ipv4/tcp_syncookies', 'w') as file:
        file.write(syncookies_status)

    now = datetime.now()
    with open('server_change_log.txt', 'a') as log_file:
        log_file.write(f'{action} syncookies at {now}\n')


def detect_packet(index: int) -> int:
    """
    tcp소켓을 통해 SYN 패킷을 감지하고 백로그 크기, SYNACK 재시도 횟수, SYN 쿠키 상태를 조정합니다.
    :return: index
    :param index: 사용자가 지정한 백로그 크기 배열의 인덱스
    """
    conn_count = get_syn_conn_status()
    print(f'Connection count: {conn_count}')
    if conn_count >= BACKLOG_LIMIT_ARRAY[index]:
        if index < len(BACKLOG_LIMIT_ARRAY) - 1:
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
            if get_synack_retries_status() != SYNACK_RETRIES:
                adjust_synack_retries(True)
            else:
                if index > 0:
                    index -= 1
                    adjust_backlog_limit(index, False)
    return index


config = configparser.ConfigParser()
config.read('config.ini')
BACKLOG_LIMIT_ARRAY = [int(x) for x in config['DEFAULT']['BACKLOG_LIMIT_ARRAY'].split(',')]
SLEEPTIME = int(config['DEFAULT']['SLEEPTIME'])
SYNACK_RETRIES = int(config['DEFAULT']['SYNACK_RETRIES'])
today = datetime.today()
filedir = "./SYN/" + str(today.year) + "/" + str(today.month) + "/"
if not os.path.exists(filedir):
    os.makedirs(filedir)
index = 0
while True:
    index = detect_packet(index)
