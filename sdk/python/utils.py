from enum import Enum
from api import *
import time
import struct
import socket
import array
import random
from typing import Dict, TypedDict,List

# 定义连接状态
class TCPState(Enum):
    CLOSED = 0
    LISTEN = 1
    SYN_SENT = 2
    SYN_RECEIVED = 3
    ESTABLISHED = 4
    FIN_WAIT_1 = 5
    FIN_WAIT_2 = 6
    CLOSE_WAIT = 7
    CLOSING = 8
    LAST_ACK = 9
    TIME_WAIT = 10

WAIT_TIME = 5 # 等待关闭的时间,s
TIMEOUT = 500 # timeout的时间,ms
MAX_RETRANSMISSION = 5 # 最大重传次数

############################################################################################################
# 维护连接状态
############################################################################################################

class Record(TypedDict):
    """
    定义一个结构体，用于记录发送的报文、时间、重传次数、序列号
    """
    seq_num: int
    packet: bytes
    time: float # 记录时间
    retry_num: int # 重传次数



def name(conn: ConnectionIdentifier)->str:
    return str(conn['src']['ip'])+str(conn['src']['port'])+str(conn['dst']["ip"])+str(conn['dst']['port'])

class Connection:
    """
    定义一个类，用于记录连接的状态
    """

    def __init__(
        self,
        conn: ConnectionIdentifier,
        state=TCPState.CLOSED,
        seq_num=0,
        ack_num=0,
        window_size=8192,
        urgent_pointer=0,
    ):
        self.conn = conn
        self.state = state
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.window_size = window_size
        self.urgent_pointer = urgent_pointer
        self.name = name(conn)
        self.retry_count = 0
        self.record:List[Record] = []
        self.cycle = 0 # 记录seq超出2**32的次数
        self.lastack = 0 # 记录接收到的最新ack
        self.wait_time = None # 记录进入TIME_WAIT状态的时间


    def get_state(self):
        return self.state

    def set_state(self, state: TCPState):
        self.state = state

    def update(
        self,
        seq_num=None,
        ack_num=None,
        window_size=None,
        urgent_pointer=None,
    ):
        if seq_num:
            self.seq_num = seq_num
        if ack_num:
            self.ack_num = ack_num
        if window_size:
            self.window_size = window_size
        if urgent_pointer:
            self.urgent_pointer = urgent_pointer
    
    def send(self,data=None,syn_flag=0,ack_flag=0,fin_flag=0,rst_flag=0,psh_flag=0,urg_flag=0):
        """
        发送tcp报文
        :param data: 数据
        :param syn_flag: SYN标志
        :param ack_flag: ACK标志
        :param fin_flag: FIN标志
        :param rst_flag: RST标志
        :param psh_flag: PSH标志
        :param urg_flag: URG标志
        :return: None
        """
        packet = create_tcp_packet(conn=self.conn,seq_num=self.seq_num,ack_num=self.ack_num,syn_flag=syn_flag,ack_flag=ack_flag,fin_flag=fin_flag,rst_flag=rst_flag,psh_flag=psh_flag,urg_flag=urg_flag,data=data)
        # 记录当前的发送，用于后面的超时重传
        if self.state not in (TCPState.CLOSE_WAIT,TCPState.FIN_WAIT_1,TCPState.FIN_WAIT_2,TCPState.TIME_WAIT):
            self.record.append(Record(seq_num=self.seq_num,packet=packet,time=time.time(),retry_num=1))
        tcp_tx(self.conn,packet)

connctions:Dict[str,Connection] = {}

def create_connection(
    conn: ConnectionIdentifier,
    state=TCPState.CLOSED,
    seq_num=0,
    ack_num=0,
    window_size=65535,
    urgent_pointer=0,
)->Connection:
    """
    创建一个连接对象
    :param conn: 连接对象
    :param state: 连接状态
    :param seq_num: 序列号
    :param ack_num: 确认号
    :param window_size: 窗口大小
    :param urgent_pointer: 紧急指针
    :return: 连接对象
    """
    my_conn = Connection(
        conn, state, seq_num, ack_num, window_size, urgent_pointer
    )
    connctions[my_conn.name] = my_conn
    return connctions[my_conn.name]

def get_connection(conn: ConnectionIdentifier)->Connection:
    """
    通过连接对象获取连接
    :param conn: 连接对象
    :return: 连接对象
    """
    if name(conn) in connctions:
        return connctions[name(conn)]
    else:
        return None

def calculate_checksum(packet: bytes)->int:
    '''
    根据报文计算校验和
    :param packet: 报文
    :return: 校验和
    '''
    if len(packet) % 2 != 0:
        packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff


def create_tcp_packet(
    conn,
    seq_num,
    ack_num,
    syn_flag=0,
    ack_flag=0,
    fin_flag=0,
    rst_flag=0,
    psh_flag=0,
    urg_flag=0,
    window_size=65535,
    urgent_pointer=0,
    data=None
):
    """
    根据输入的参数产生tcp报文
    :param conn: 连接对象
    :param seq_num: 序列号
    :param ack_num: 确认号
    :param syn_flag: SYN标志
    :param ack_flag: ACK标志
    :param fin_flag: FIN标志
    :param rst_flag: RST标志
    :param psh_flag: PSH标志
    :param urg_flag: URG标志
    :param window_size: 窗口大小
    :param urgent_pointer: 紧急指针
    :param data: 数据
    :return: tcp报文
    """
    flags = (
        urg_flag << 5
        | ack_flag << 4
        | psh_flag << 3
        | rst_flag << 2
        | syn_flag << 1
        | fin_flag
    )
    packet = struct.pack(
        '!HHIIBBHHH',
        conn['src']['port'], # Source Port
        conn['dst']['port'], # Destination Port
        seq_num, # Sequence Number
        ack_num, # Acknoledgement Number
        5 << 4, # Data Offset
        flags, # Flags
        window_size, # Window
        0, # Checksum (initial value)
        urgent_pointer # Urgent pointer
    )

    if isinstance(data,bytes):
        packet = packet+data

    fake_head = struct.pack(
        '!4s4sHH',
        socket.inet_aton(conn['src']['ip']), 
        socket.inet_aton(conn['dst']['ip']), 
        socket.IPPROTO_TCP, 
        len(packet)
    )

    return packet[:16] + struct.pack('H', calculate_checksum(fake_head+packet)) + packet[18:]

def get_tcp_info(data: bytes):
    """
    从tcp报文中提取信息
    :param data: tcp报文
    """
    source_port = int.from_bytes(data[0:2], byteorder="big")
    destination_port = int.from_bytes(data[2:4], byteorder="big")
    seq_num = int.from_bytes(data[4:8], byteorder="big")
    ack_num = int.from_bytes(data[8:12], byteorder="big")
    data_offset_reserved_flags = int.from_bytes(data[12:14], byteorder="big")
    data_offset = data_offset_reserved_flags >> 12
    flags = data_offset_reserved_flags & 0x3F
    reserved = (data_offset_reserved_flags >> 6) & 0x3F
    syn_flag = (flags >> 1) & 0x1
    ack_flag = (flags >> 4) & 0x1
    fin_flag = flags & 0x1
    rst_flag = (flags >> 2) & 0x1
    psh_flag = (flags >> 3) & 0x1
    urg_flag = (flags >> 5) & 0x1
    window_size = int.from_bytes(data[14:16], byteorder="big")
    checksum = int.from_bytes(data[16:18], byteorder="big")
    urgent_pointer = int.from_bytes(data[18:20], byteorder="big")
    data = data[data_offset*4:]
    return {
        "source_port": source_port,
        "destination_port": destination_port,
        "seq_num": seq_num,
        "ack_num": ack_num,
        "data_offset": data_offset,
        "reserved": reserved,
        "syn_flag": syn_flag,
        "ack_flag": ack_flag,
        "fin_flag": fin_flag,
        "rst_flag": rst_flag,
        "psh_flag": psh_flag,
        "urg_flag": urg_flag,
        "window_size": window_size,
        "checksum": checksum,
        "urgent_pointer": urgent_pointer,
        "data": data,
    }