"""
这是等待你完成的代码。正常情况下，本文件是你唯一需要改动的文件。
你可以任意地改动此文件，改动的范围当然不限于已有的五个函数里。（只要已有函数的签名别改，要是签名改了main里面就调用不到了）
在开始写代码之前，请先仔细阅读此文件和api文件。这个文件里的五个函数是等你去完成的，而api里的函数是供你调用的。
提示：TCP是有状态的协议，因此你大概率，会需要一个什么样的数据结构来记录和维护所有连接的状态
"""

# from api import ConnectionIdentifier
from api import *
from enum import Enum
import random

############################################################################################################
# 维护连接状态
############################################################################################################
connctions = {}

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
        window_size=0,
        checksum=0,
        urgent_pointer=0,
    ):
        self.conn = conn
        self.state = state
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.window_size = window_size
        self.checksum = checksum
        self.urgent_pointer = urgent_pointer

    def get_state(self):
        return self.state

    def set_state(self, state: TCPState):
        self.state = state


def create_connection(
    conn: ConnectionIdentifier,
    state=TCPState.CLOSED,
    seq_num=0,
    ack_num=0,
    window_size=0,
    checksum=0,
    urgent_pointer=0,
):
    connctions[conn] = Connection(
        conn, state, seq_num, ack_num, window_size, checksum, urgent_pointer
    )


def get_connection(conn: ConnectionIdentifier):
    if conn in connctions:
        return connctions[conn]
    else:
        connctions[conn] = Connection(conn)
        return connctions[conn]


############################################################################################################
# 功能函数
############################################################################################################
def app_connect(conn: ConnectionIdentifier):
    """
    当有应用想要发起一个新的连接时，会调用此函数。想要连接的对象在conn里提供了。
    你应该向想要连接的对象发送SYN报文，执行三次握手的逻辑。
    当连接建立好后，你需要调用app_connected函数，通知应用层连接已经被建立好了。
    :param conn: 连接对象
    :return:
    """
    # TODO 请实现此函数
    source_port = conn.src.port
    destination_port = conn.dst.port
    # 初始序列号
    seq_num = random.randiant(0, 2**32 - 1)
    ack_num = 0
    # 第一次握手
    syn_flag = 1  # SYN标志位为1
    tcp_header = create_tcp_header(
        source_port, destination_port, seq_num, ack_num, syn_flag=syn_flag
    )
    tcp_tx(conn, tcp_header)

    # 第二次握手

    # 第三次握手

    app_connected(conn)
    print("app_connect", conn)


def create_tcp_header(
    source_port,
    destination_port,
    seq_num,
    ack_num,
    syn_flag=0,
    ack_flag=0,
    fin_flag=0,
    rst_flag=0,
    psh_flag=0,
    urg_flag=0,
    window_size=0,
    checksum=0,
    urgent_pointer=0,
):
    """
    创建TCP报文头部，返回TCP报文头部
    """
    # 16位源端口号
    source_port = source_port.to_bytes(2, byteorder="big")
    # 16位目的端口号
    destination_port = destination_port.to_bytes(2, byteorder="big")
    # 32位序列号
    seq_num = seq_num.to_bytes(4, byteorder="big")
    # 32位确认号
    ack_num = ack_num.to_bytes(4, byteorder="big")
    # 4位首部长度
    data_offset = 5
    # 6位保留位
    reserved = 0
    # 检查标志位是否都为0或1
    assert all(
        flag in (0, 1)
        for flag in (syn_flag, ack_flag, fin_flag, rst_flag, psh_flag, urg_flag)
    ), "Invalid flag value!"
    flags = (
        urg_flag << 5
        | ack_flag << 4
        | psh_flag << 3
        | rst_flag << 2
        | syn_flag << 1
        | fin_flag
    )
    data_offset_reserved_flags = data_offset << 12 | reserved << 6 | flags
    data_offset_reserved_flags = data_offset_reserved_flags.to_bytes(2, byteorder="big")
    # 16位窗口大小
    window_size = window_size.to_bytes(2, byteorder="big")
    # 16位校验和，后面更新
    checksum = 0
    # 16位紧急指针
    urgent_pointer = urgent_pointer.to_bytes(2, byteorder="big")

    # 计算校验和
    fake_tcp_header = (
        source_port
        + destination_port
        + seq_num
        + ack_num
        + data_offset_reserved_flags
        + window_size
        + urgent_pointer
    )
    checksum = calculate_checksum(fake_tcp_header)
    # TCP报文头部
    fake_tcp_header = (
        source_port
        + destination_port
        + seq_num
        + ack_num
        + data_offset
        + reserved
        + flags
        + window_size
        + checksum
        + urgent_pointer
    )

    # 更新data_offset
    length = len(fake_tcp_header)
    new_data_offset = length // 4

    if data_offset == new_data_offset:
        tcp_header = fake_tcp_header
    else:
        data_offset = new_data_offset
        data_offset_reserved_flags = data_offset << 12 | reserved << 6 | flags
        data_offset_reserved_flags = data_offset_reserved_flags.to_bytes(
            2, byteorder="big"
        )
        tcp_header = (
            source_port
            + destination_port
            + seq_num
            + ack_num
            + data_offset_reserved_flags
            + window_size
            + checksum
            + urgent_pointer
        )

    return tcp_header


def calculate_checksum(data: bytes) -> bytes:
    """
    计算校验和，返回16字节的checksum
    """
    checksum = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            checksum += (data[i] << 8) + data[i + 1]
        elif i + 1 == len(data):
            checksum += data[i]
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = ~checksum & 0xFFFF
    return checksum.to_bytes(2, byteorder="big")


def app_send(conn: ConnectionIdentifier, data: bytes):
    """
    当应用层想要在一个已经建立好的连接上发送数据时，会调用此函数。
    :param conn: 连接对象
    :param data: 数据内容，是字节数组
    :return:
    """
    # TODO 请实现此函数
    print("app_send", conn, data.decode(errors="replace"))


def app_fin(conn: ConnectionIdentifier):
    """
    当应用层想要半关闭连接(FIN)时，会调用此函数。
    :param conn: 连接对象
    :return:
    """
    # TODO 请实现此函数
    print("app_fin", conn)


def app_rst(conn: ConnectionIdentifier):
    """
    当应用层想要重置连接(RES)时，会调用此函数
    :param conn: 连接对象
    :return:
    """
    # TODO 请实现此函数
    print("app_rst", conn)


def tcp_rx(conn: ConnectionIdentifier, data: bytes):
    """
    当收到TCP报文时，会调用此函数。
    正常情况下，你会对TCP报文，根据报文内容和连接的当前状态加以处理，然后调用0个~多个api文件中的函数
    :param conn: 连接对象
    :param data: TCP报文内容，是字节数组。（含TCP报头，不含IP报头）
    :return:
    """
    # TODO 请实现此函数
    tcp_info = {}
    tcp_info = get_tcp_info(data)
    print("tcp_rx", conn, data.decode(errors="replace"))
    return tcp_info


def get_tcp_info(data: bytes):
    tcp_info = {}
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
    tcp_info["source_port"] = source_port
    tcp_info["destination_port"] = destination_port
    tcp_info["seq_num"] = seq_num
    tcp_info["ack_num"] = ack_num
    tcp_info["data_offset"] = data_offset
    tcp_info["reserved"] = reserved
    tcp_info["syn_flag"] = syn_flag
    tcp_info["ack_flag"] = ack_flag
    tcp_info["fin_flag"] = fin_flag
    tcp_info["rst_flag"] = rst_flag
    tcp_info["psh_flag"] = psh_flag
    tcp_info["urg_flag"] = urg_flag
    tcp_info["window_size"] = window_size
    tcp_info["checksum"] = checksum
    tcp_info["urgent_pointer"] = urgent_pointer
    return tcp_info


def tick():
    """
    这个函数会每至少100ms调用一次，以保证控制权可以定期的回到你实现的函数中，而不是一直阻塞在main文件里面。
    它可以被用来在不开启多线程的情况下实现超时重传等功能，详见主仓库的README.md
    """
    # TODO 可实现此函数，也可不实现
    pass
