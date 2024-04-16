from typing import TypedDict


class Record(TypedDict):
    # 定义一个结构体，用于记录发送的时间
    seq_num: int = 0
    packet: bytes = b""
    time: float = 0  # 记录时间
    retry_num: int = 0  # 重传次数


def get_record(i):
    return Record(seq_num=i, packet=b"", time=0, retry_num=0)

b= []
for _ in range(10):
    b.append(get_record(_))

for i in b:
    if i["seq_num"] == 5:
        b.remove(i)

print(b)
