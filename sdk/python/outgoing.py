"""
这是等待你完成的代码。正常情况下，本文件是你唯一需要改动的文件。
你可以任意地改动此文件，改动的范围当然不限于已有的五个函数里。（只要已有函数的签名别改，要是签名改了main里面就调用不到了）
在开始写代码之前，请先仔细阅读此文件和api文件。这个文件里的五个函数是等你去完成的，而api里的函数是供你调用的。
提示：TCP是有状态的协议，因此你大概率，会需要一个什么样的数据结构来记录和维护所有连接的状态
"""

from utils import *

# 测试用
verbose = 1


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
    # 创建一个Connection，seq_num为最初随机的序列号
    my_conn = create_connection(conn, seq_num=random.randint(0, 2**32 - 1))
    # 第一次握手
    # 发送SYN报文
    my_conn.send(syn_flag=1)
    # 更新连接状态
    my_conn.set_state(TCPState.SYN_SENT)
    my_conn.seq_num = my_conn.seq_num + 1
    if verbose:
        print("app_connect", conn)


def app_send(conn: ConnectionIdentifier, data: bytes):
    """
    当应用层想要在一个已经建立好的连接上发送数据时，会调用此函数。
    :param conn: 连接对象
    :param data: 数据内容，是字节数组
    :return:
    """
    my_conn = get_connection(conn)
    my_conn.send(data=data, ack_flag=1, psh_flag=1)
    # 更新seq
    my_conn.seq_num += len(data)
    if verbose:
        print("app_send", conn, data.decode(errors="replace"))


def app_fin(conn: ConnectionIdentifier):
    """
    当应用层想要半关闭连接(FIN)时，会调用此函数。
    :param conn: 连接对象
    :return:
    """
    my_conn = get_connection(conn)
    my_conn.send(fin_flag=1, ack_flag=1)
    my_conn.seq_num += 1
    my_conn.set_state(TCPState.FIN_WAIT_1)
    if verbose:
        print("app_fin", conn)
        print("State: FIN_WAIT_1")


def app_rst(conn: ConnectionIdentifier):
    """
    当应用层想要重置连接(RES)时，会调用此函数
    :param conn: 连接对象
    :return:
    """
    my_conn = get_connection(conn)
    my_conn.send(rst_flag=1, ack_flag=1)
    if verbose:
        print("app_rst", conn)


def tcp_rx(conn: ConnectionIdentifier, data: bytes):
    """
    当收到TCP报文时，会调用此函数。
    正常情况下，你会对TCP报文，根据报文内容和连接的当前状态加以处理，然后调用0个~多个api文件中的函数
    :param conn: 连接对象
    :param data: TCP报文内容，是字节数组。（含TCP报头，不含IP报头）
    :return:
    """
    tcp_info = {}
    tcp_info = get_tcp_info(data)
    my_conn = get_connection(conn)
    # 几种特殊情况，优先考虑
    if tcp_info["rst_flag"] == 1:
        # 对端要求重置连接
        app_peer_rst(conn)

    elif my_conn is None or my_conn.get_state() == TCPState.CLOSED:
        app_rst(conn)

    # 如果此时连接状态为ESTABLISHED，说明可能收到数据
    elif my_conn.get_state() == TCPState.ESTABLISHED:
        if tcp_info["fin_flag"]:
            # 对端要求半关闭连接
            if my_conn.lastack > tcp_info["ack_num"]:
                # 如果上次的确认号比当前收到的确认号大，说明已经超过2**32进入下一次循环
                my_conn.cycle += 1
            my_conn.lastack = tcp_info["ack_num"]
            my_conn.ack_num = tcp_info["seq_num"] + 1
            my_conn.set_state(TCPState.CLOSE_WAIT)
            my_conn.send(ack_flag=1)
            # 发送ACK后，通知应用层进行半关闭
            app_peer_fin(conn)
            # 进行第三次挥手，发送FIN
            my_conn.set_state(TCPState.LAST_ACK)
            my_conn.send(fin_flag=1, ack_flag=1)
            my_conn.seq_num += 1

        else:
            if my_conn.lastack > tcp_info["ack_num"]:
                # 如果上次的确认号比当前收到的确认号大，说明已经超过2**32进入下一次循环
                my_conn.cycle += 1
            my_conn.lastack = tcp_info["ack_num"]
            if len(tcp_info["data"]) > 0:
                # 判断是否当前的收到报文的seq是否为当前记录的ack
                if my_conn.ack_num == tcp_info["seq_num"]:
                    my_conn.ack_num = tcp_info["seq_num"] + len(tcp_info["data"])
                # 回复收到数据的报文
                my_conn.send(ack_flag=1)
                app_recv(conn, tcp_info["data"])

    # 如果此时连接状态为SYN_SENT，即处于第二次握手状态
    elif my_conn.get_state() == TCPState.SYN_SENT:
        if tcp_info["syn_flag"] and tcp_info["ack_flag"]:
            if my_conn.lastack > tcp_info["ack_num"]:
                # 如果上次的确认号比当前收到的确认号大，说明已经超过2**32进入下一次循环
                my_conn.cycle += 1
            my_conn.lastack = tcp_info["ack_num"]
            my_conn.ack_num = tcp_info["seq_num"] + 1
            my_conn.set_state(TCPState.ESTABLISHED)
            my_conn.send(ack_flag=1)
            app_connected(conn)
            if verbose:
                print("第三次握手成功连接")
        else:
            if verbose:
                print("第二次握手失败")

    elif my_conn.get_state() == TCPState.FIN_WAIT_2:
        # 接受server端未发送完的数据
        # app_recv(conn,tcp_info["data"])
        if tcp_info["fin_flag"]:
            # 半关闭请求
            my_conn.set_state(TCPState.TIME_WAIT)
            my_conn.wait_time = time.time()
            app_peer_fin(conn)
            my_conn.update(seq_num=tcp_info["ack_num"], ack_num=tcp_info["seq_num"] + 1)
            my_conn.send(ack_flag=1)
            print("State: TIME_WAIT_1")

    elif my_conn.get_state() == TCPState.FIN_WAIT_1:
        if tcp_info["ack_flag"] and not tcp_info["fin_flag"]:
            if my_conn.lastack > tcp_info["ack_num"]:
                # 如果上次的确认号比当前收到的确认号大，说明已经超过2**32进入下一次循环
                my_conn.cycle += 1
            my_conn.lastack = tcp_info["ack_num"]
            my_conn.set_state(TCPState.FIN_WAIT_2)
            my_conn.ack_num = tcp_info["seq_num"]
            if verbose:
                print("State: FIN_WAIT_2")

        elif tcp_info["fin_flag"] and tcp_info["ack_flag"]:
            # 直接进入TIME_WAIT阶段
            if my_conn.lastack > tcp_info["ack_num"]:
                # 如果上次的确认号比当前收到的确认号大，说明已经超过2**32进入下一次循环
                my_conn.cycle += 1
            my_conn.lastack = tcp_info["ack_num"]
            my_conn.wait_time = time.time()
            my_conn.send(ack_flag=1)
            my_conn.set_state(TCPState.TIME_WAIT)
            if verbose:
                print("State:TIME_WAIT_2")

        elif tcp_info["fin_flag"] and not tcp_info["ack_flag"]:
            # 进入CLOSING状态
            if my_conn.lastack > tcp_info["ack_num"]:
                # 如果上次的确认号比当前收到的确认号大，说明已经超过2**32进入下一次循环
                my_conn.cycle += 1
            my_conn.lastack = tcp_info["ack_num"]
            # 通知应用层半关闭
            app_peer_fin(conn)
            my_conn.ack_num = tcp_info["seq_num"] + 1
            my_conn.send(ack_flag=1)

    elif my_conn.get_state() == TCPState.CLOSING:
        # 如果收到ACK
        if tcp_info["ack_flag"]:
            my_conn.set_state(TCPState.TIME_WAIT)
            my_conn.wait_time = time.time()
            if verbose:
                print("State: TIME_WAIT_3")

    # print("tcp_rx", conn, data.decode(errors="replace"))
    # return tcp_info


def tick():
    """
    这个函数会每至少100ms调用一次，以保证控制权可以定期的回到你实现的函数中，而不是一直阻塞在main文件里面。
    它可以被用来在不开启多线程的情况下实现超时重传等功能，详见主仓库的README.md
    """
    topop = []
    for conn_name, my_conn in connctions.items():
        if my_conn.state == TCPState.CLOSED:
            # 如果当前连接的状态已关闭，则不需要重传
            continue
        for r in my_conn.record:
            if time.time() - r["time"] > TIMEOUT / 1000 * 2 ** (r["retry_num"] - 1):
                if verbose:
                    print(time.time())
                    print(r)
                # 如果当前时间比记录时间超出，timeout的2的重传次数-1次幂，则说明已超时
                if my_conn.lastack + my_conn.cycle * (1 << 32) <= r["seq_num"]:

                    # 如果最后一次确认的ack比seq更大，说明已经成功发送；反之，需要重传
                    if r["retry_num"] > MAX_RETRANSMISSION:
                        # 如果当前重传次数已超过最大重传次数，说明连接存在问题，请求rst
                        my_conn.set_state(TCPState.CLOSED)
                        app_rst(conn=my_conn.conn)
                        app_peer_rst(my_conn.conn)
                    else:
                        # 继续重传，更新record中的内容，更新时间和重传次数
                        r["time"] = time.time()
                        r["retry_num"] += 1
                        tcp_tx(my_conn.conn, r["packet"])
                else:
                    # 说明重传已成功
                    pass
        if my_conn.get_state() == TCPState.TIME_WAIT:
            # 如果当前状态为TIME_WAIT，则需要等待WAIT_TIME时间，然后释放连接
            if time.time() - my_conn.wait_time > WAIT_TIME:
                # 达到等待的时间
                topop.append(conn_name)
                # print(topop)
                release_connection(my_conn.conn)
    for name in topop:
        connctions.pop(name)
        if verbose:
            print("Connection Pop")
