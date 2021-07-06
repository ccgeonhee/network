import dpkt
import socket

with open('imgtest.pcap', 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    var = 110
    dic = {}

    for timestamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        var = var - 1

        if var == 0:
            break
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        print('Timestamp: ', timestamp)
        print('IP: %s -> %s len=%d' % (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ip.len))
        print('Port : %d -> %d ack=%d seq=%d' % (tcp.sport, tcp.dport, tcp.ack, tcp.seq))
        print('Payload: ', str(tcp.data))

        streamIndex = socket.inet_ntoa(ip.src) + str(tcp.sport) + socket.inet_ntoa(ip.dst) + str(tcp.dport) + str(tcp.ack)
        print('StreamIndex: ', streamIndex)

        if streamIndex in dic:
            streamIndexValue = dic[streamIndex]
            streamIndexValue += ':' + str(tcp.seq) + ',' + str(tcp.data)
            del dic[streamIndex]
            dic[streamIndex] = streamIndexValue
        else:
            dic[streamIndex] = str(tcp.seq) + ',' + str(tcp.data)

sort = [[] for i in range(len(dic))]
sequence = [[]for j in range(len(dic))]
payload = [[] for k in range(len(dic))]
value = list(dic.values())
temp = ''
for i in range(len(value)):
    temp = value[i]
    if temp.find('구분') != -1:
        for j in range(temp.count('구분')+1):
            if temp.find('구분') == -1:
                sort[i].append(temp)
                count2 = sort[i][j].find('구분2')
                sequence[i].append(sort[i][j][:count2])
                payload[i].append(sort[i][j][count2+2:])
            else:
                count = temp.find('구분')
                sort[i].append(temp[:count])
                count2 = sort[i][j].find('구분2')
                sequence[i].append(sort[i][j][:count2])
                payload[i].append(sort[i][j][count2+2:])
                temp = temp[count + 2:]
    elif temp.find('구분') == -1:
        sort[i].append(temp)
        count2 = sort[i][0].find('구분2')
        sequence[i].append(sort[i][0][:count2])
        payload[i].append(sort[i][0][count2 + 2:])
for i in range(len(sequence)):
    for j in range(len(sequence[i]), 0, -1):
        max = 0
        for k in range(0,j):
            if sequence[i][k] > sequence[i][max]:
                max = k
        sequence[i][max], sequence[i][k] = sequence[i][k],sequence[i][max]
        payload[i][max], payload[i][k] = payload[i][k], payload[i][max]

total_payload = []
for i in range(len(payload)):
    tmp = ''
    for j in range(len(payload[i])):
        tmp += payload[i][j]
    total_payload.append(tmp)

SIG_JPEG = "FFD8FFE0"
SIG_JPEG2 = "FFD8FFE1"
SIG_JPEG3 = "FFD8FFE8"
SIG_JPEG_END = "FFD9"

pic_data = []

for i in range(len(total_payload)):
    tmp = total_payload[i]
    if tmp.find(SIG_JPEG) != -1 and tmp.find(SIG_JPEG_END) != -1 and tmp.find(SIG_JPEG) < tmp.find(SIG_JPEG_END):
        pic_data.append(tmp[tmp.find(SIG_JPEG):])
    elif tmp.find(SIG_JPEG2) != -1 and tmp.find(SIG_JPEG_END) != -1 and tmp.find(SIG_JPEG2) < tmp.find(SIG_JPEG_END):
        pic_data.append(tmp[tmp.find(SIG_JPEG2):])
    elif tmp.find(SIG_JPEG3) != -1 and tmp.find(SIG_JPEG_END) != -1 and tmp.find(SIG_JPEG3) < tmp.find(SIG_JPEG_END):
        pic_data.append(tmp[tmp.find(SIG_JPEG2):])

temp_pic_data = ''
for i in range(len(pic_data)):
    temp_pic_data = bytes.fromhex(pic_data[i])
    with open('image' + str(i) + '.jpeg', 'wb') as file:
        file.write(temp_pic_data)