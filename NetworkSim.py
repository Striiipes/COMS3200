import sys
import socket
import ipaddress
from threading import Thread
from threading import Timer 
import threading
from time import *
import math
import os

def proto_114_response(port, destination, id):
    packet = bytearray()
    packet.append(0b01000000) # Version + IHL.
    packet.append(0b00000000) # TOS.
    packet.append(0b11111111) # Total Length -> lower.
    packet.append(0b11111111) # Total Length -> upper.
    packet.append(0b00000000) # Identification -> upper.
    packet.append(id) # Identification -> lower.
    packet.append(0b00000000) # Flags -> upper.
    packet.append(0b01010101) # Flags -> lower.
    packet.append(0b11111111) # TTL.
    packet.append(0b01110010) # Protocol (114).
    packet.append(0b00000000) # Checksum -> upper.
    packet.append(0b00000000) # Checksum -> lower.
    destination = destination.split(".")
    packet.append(int(destination[0])) # Append destination address.
    packet.append(int(destination[1]))
    packet.append(int(destination[2]))
    packet.append(int(destination[3]))
    my_ip = sys.argv[1] 
    my_ip = my_ip.split("/")
    my_ip = str(my_ip[0])
    my_ip = my_ip.split(".")
    packet.append(int(my_ip[0])) # Append source address.
    packet.append(int(my_ip[1]))
    packet.append(int(my_ip[2]))
    packet.append(int(my_ip[3]))
    server_to_send = ("localhost", int(port))
    sock.sendto(packet, server_to_send)
            
def non_fragment(data, address):
    sys.stdout.write("\b") # Wipe any existing command line entries.
    sys.stdout.write("\b")
    sys.stdout.write("\b")
    sys.stdout.write("\b")
    ip_sent = "" # Format IP address.
    ip_sent += str(data[12])
    ip_sent += "."
    ip_sent += str(data[13])
    ip_sent += "."
    ip_sent += str(data[14])
    ip_sent += "."
    ip_sent += str(data[15])
    payload = str(data[20:]) # Append payload information.
    payload = payload[1:]
    payload = payload.replace("'", '"') # Replace any extra information.
    if int(str(data[9])) == 0:
        print("Message received from ", end='', flush=True)
        print(ip_sent, end='', flush=True)
        print(": ", end='', flush=True)
        print(payload, flush=True) # Flush outputs.
    else:
        print("Message received from ", end='', flush=True)
        print(ip_sent, end='', flush=True)
        print(" with protocol 0x", end='', flush=True)
        fmt = str(data[9])
        fmt_u = "0"
        if len(fmt) < 2:
            fmt_u += fmt
            print(fmt_u, flush=True) # Append 0x for protocol print.
        else: 
            print(fmt, flush=True) 
    print("> ",end='', flush=True)

def fragment(data, ip, port):
    sys.stdout.write("\b") # Wipe any existing entries.
    sys.stdout.write("\b")
    sys.stdout.write("\b")
    sys.stdout.write("\b")
    global recv_packets
    rest_of_packet = "" # Format packets.
    for i in range(100):
        if recv_packets[i][0] == ip:
            rest_of_packet += recv_packets[i][2]
            break
    payload = ""
    rest_of_packet = str(rest_of_packet)
    rest_of_packet.replace("'", '')
    payload += rest_of_packet
    format_str = '"'
    format_str += payload
    format_str += '"'
    ip_sent = "" # Append IP address.
    ip_sent += str(data[12])
    ip_sent += "."
    ip_sent += str(data[13])
    ip_sent += "."
    ip_sent += str(data[14])
    ip_sent += "."
    ip_sent += str(data[15])
    format_str = format_str.replace("+", "") # Remove custom message.
    format_str = format_str.replace("'", "")
    if int(str(data[9])) == 0:
        print("Message received from ", end='', flush=True)
        print(ip_sent, end='', flush=True)
        print(": ", end='', flush=True)
        print(format_str, flush=True)
    else:
        print("Message received from ", end='', flush=True) # Append protocol information.
        print(ip_sent, end='', flush=True)
        print(" with protocol 0x", end='', flush=True)
        fmt = str(data[9])
        fmt_u = "0"
        if len(fmt) < 2:
            fmt_u += fmt
            print(fmt_u, flush=True)
        else: 
            print(fmt, flush=True) 
    print("> ",end='', flush=True) # Return previous input.
    
def get_address(data): # Convert 192, 168, 1, 2 to 192.168.1.2.
    address = ""
    address += str(data[12])
    address += "."
    address += str(data[13])
    address += "."
    address += str(data[14])
    address += "."
    address += str(data[15])
    return address
    
def decipher_packet(data, address):
    global recv_packets
    global frto
    ip = get_address(data)
    port = int(address[1])
    payload = str(data[20:])
    id = int(data[4]) + int(data[5])
    updated_packet = False
    for i in range(100): # Already got this ID.
        if recv_packets[i][0] == ip:
            if recv_packets[i][1] == port:
                if recv_packets[i][4] == id:
                    updated_packet = True
                    # Make sure we haven't already run out of time.
                    recv_packets[i][2] += "+"
                    recv_packets[i][2] += payload[1:]
                    recv_packets[i][4] = int(data[4]) + int(data[5])
                    updated_packet = True
                    if int(data[6]) == 0:
                        fragment(data, ip, port)
                        # Empty the packet entry. No longer needed.
                        recv_packets[i][0] = 0
                        recv_packets[i][1] = 0
                        recv_packets[i][2] = ""
                        recv_packets[i][3] = 0
                        recv_packets[i][4] = 0
        break        
    if updated_packet == False: # New packet ID.
        index = 0
        for i in range(100):
            if recv_packets[i][0] == 0: # Found an empty slot in the sent_packets table.
                recv_packets[i][0] = ip # Set the IP.
                recv_packets[i][1] = port # Set the port number.
                recv_packets[i][2] += payload[1:] # Set the first part of the payload.
                recv_packets[i][4] = int(data[4]) + int(data[5]) # Set the ID of the packet.
                index = i
                break 
        if int(data[6]) == 0: # Single non-fragmented packet.
            non_fragment(data, address)
            recv_packets[index][0] = 0 # IP address.
            recv_packets[index][1] = 0 # Port number.
            recv_packets[index][2] = "" # Payload. 
            recv_packets[index][3] = 0 # Fragment flag.
            recv_packets[index][4] = 0 # ID of original packet.
        else:
            sleep(frto)
            for j in range(100):
                if recv_packets[j][4] == id:
                    recv_packets[j][3] = 1
                    proto_114_response(recv_packets[j][1], recv_packets[j][0], recv_packets[j][4])
                    # Empty old packet entry.
                    recv_packets[j][0] = 0 # IP address.
                    recv_packets[j][1] = 0 # Port number.
                    recv_packets[j][2] = "" # Payload.
                    recv_packets[j][3] = 0 # Fragment flag.
                    recv_packets[j][4] = 0 # ID of original packet.

def resend_packet(data, address, id_find):
    global sent_packets
    global mtu
    ip = get_address(data)
    for i in range(100):
        if sent_packets[i][3] == id_find:
            payload = sent_packets[i][2]
            number_of_pkts = math.ceil((len(payload) + 20) / mtu)
            if number_of_pkts == 1:
                frame = bytearray()
                frame.append(0b01000000) # Version + IHL.
                frame.append(0b00000000) # TOS.
                frame.append(0b11111111) # Total Length -> lower.
                frame.append(0b11111111) # Total Length -> upper.
                frame.append(0b00000000) # Identification -> upper.
                frame.append(id_find) # Identification -> lower.
                frame.append(0b00000000) # Flags -> upper.
                frame.append(0b01010101) # Flags -> lower.
                frame.append(0b11111111) # TTL.
                frame.append(0b00000000) # Protocol.
                frame.append(0b00000000) # Checksum -> upper.
                frame.append(0b01010101) # Checksum -> lower.
                src = sent_packets[i][0]
                src = src.split('.')
                dst = sys.argv[1]
                dst = dst.split('/')
                dst = dst[0]
                dst = dst.split('.')
                frame.append(int(dst[0])) # Add source IP.
                frame.append(int(dst[1]))
                frame.append(int(dst[2])) 
                frame.append(int(dst[3]))
                frame.append(int(src[0])) # Add destination IP.
                frame.append(int(src[1])) 
                frame.append(int(src[2])) 
                frame.append(int(src[3]))  
                for l in payload.encode(): # Encode payload.
                    frame.append(l)
                server_to_send = ("localhost", int(sent_packets[i][1]))
                sock.sendto(frame, server_to_send)
                sent_packets[i][0] = 0 # IP address.
                sent_packets[i][1] = 0 # Port number.
                sent_packets[i][2] = "" # Payload.
                sent_packets[i][3] = 0 # Fragment flag.               
            else:
                for j in range(number_of_pkts):
                    frame = bytearray()
                    frame.append(0b01000000) # Version + IHL.
                    frame.append(0b00000000) # TOS.
                    frame.append(0b11111111) # Total Length -> lower.
                    frame.append(0b11111111) # Total Length -> upper.
                    frame.append(0b00000000) # Identification -> upper.
                    frame.append(id_find) # Identification -> lower.
                    frame.append(0b00000000) # Flags -> upper.
                    frame.append(0b01010101) # Flags -> lower.
                    frame.append(0b11111111) # TTL.
                    frame.append(0b00000000) # Protocol.
                    frame.append(0b00000000) # Checksum -> upper.
                    frame.append(0b01010101) # Checksum -> lower.
                    src = sent_packets[i][0]
                    src = src.split('.')
                    dst = sys.argv[1]
                    dst = dst.split('/')
                    dst = dst[0]
                    dst = dst.split('.')
                    frame.append(int(dst[0])) # Add source IP.
                    frame.append(int(dst[1]))
                    frame.append(int(dst[2])) 
                    frame.append(int(dst[3]))
                    frame.append(int(src[0])) # Add destination IP.
                    frame.append(int(src[1])) 
                    frame.append(int(src[2])) 
                    frame.append(int(src[3]))  
                    adder = ""
                    new_range = mtu - 20
                    for j in range(new_range): # Add payload minus MTU.
                        try:
                            adder += payload[j]
                        except:
                            pass
                    for fragged_pckt in adder.encode():
                        frame.append(fragged_pckt)
                    server_to_send = ("localhost", int(sent_packets[i][1]))
                    sock.sendto(frame, server_to_send)
                    payload = payload[mtu-20:]
                sent_packets[i][0] = 0 # IP address.
                sent_packets[i][1] = 0 # Port number.
                sent_packets[i][2] = "" # Payload.
                sent_packets[i][3] = 0 # Fragment flag.

def retreive_pckt(data, address): # Format retrieved packet.
    ip = get_address(data)
    global sent_packets
    global packet_counter
    sys.stdout.write("\b") # Wipe any existing entries.
    sys.stdout.write("\b")
    sys.stdout.write("\b")
    sys.stdout.write("\b")
    id_find = int(data[4]) + int(data[5])
    id_bool = False
    for i in range(100):
        if sent_packets[i][3] == id_find: # Found IP.
            print("Message-Resend received from", ip, "for id 0x", flush=True, end='')
            id_bool = True
            fmt = str(id_find)
            fmt_u = "0"
            if len(fmt) < 2:
                fmt_u += fmt
                print(fmt_u, flush=True)
            else: 
                print(fmt, flush=True)
            resend_packet(data, address, id_find)
            break
    if id_bool == False: # Failed to find IP.
        print("Message-Resend received from", ip, "for id 0x", flush=True, end='')
        fmt = str(id_find)
        fmt_u = "0"
        if len(fmt) < 2:
            fmt_u += fmt
            print(fmt_u, "BAD", flush=True)
        else: 
            print(fmt, "BAD", flush=True) 
    print("> ",end='', flush=True)
                                                 
def thread_udp():
    sock.settimeout(1)
    global sent_packets
    try:
        while True:
            data, address = sock.recvfrom(int(LL_addr))
            if int(data[9]) == 114: # Recevied message with protocol 114.
                thread_retrive = retreive_pckt(data, address)
                thread_retrive.start()
            else: # Recevied message in accurate format.
                thread_decipher = Thread(target=decipher_packet(data, address))
                thread_decipher.start()
    except socket.timeout:
        pass

def build_pkt(ip, port, payload):
    global prev
    global frto
    global mtu
    global recv_packets
    global sent_packets
    global packet_counter
    counter = 0
    number_of_pkts = math.ceil((len(payload) + 20) / mtu)
    if number_of_pkts > 1:
        payload = payload[1:]
        payload = payload[:-1]
        for i in range(number_of_pkts):
            frame = bytearray()
            frame.append(0b01000000) # Version + IHL.
            frame.append(0b00000000) # TOS.
            frame.append(0b11111111) # Total Length -> lower.
            frame.append(0b11111111) # Total Length -> upper.
            frame.append(0b00000000) # Identification -> upper.
            frame.append(packet_counter) # Identification -> lower.
            sent_packets[packet_counter][3] = packet_counter
            if i + 1 != number_of_pkts:
                flags = 0b00100000
            else:
                flags = 0b00000000
            frame.append(flags) # Flags -> upper.
            frame.append(0b01010101) # Flags -> lower.
            frame.append(0b11111111) # TTL.
            frame.append(0b00000000) # Protocol.
            frame.append(0b00000000) # Checksum -> upper.
            frame.append(0b01010101) # Checksum -> lower.
            sent_packets[packet_counter][0] = ip
            src = ip.split('.')
            dst = sys.argv[1]
            dst = dst.split('/')
            dst = dst[0]
            dst = dst.split('.')
            frame.append(int(dst[0])) # Add source IP.
            frame.append(int(dst[1]))
            frame.append(int(dst[2])) 
            frame.append(int(dst[3]))
            frame.append(int(src[0])) # Add destination IP.
            frame.append(int(src[1])) 
            frame.append(int(src[2])) 
            frame.append(int(src[3]))  
            adder = ""
            new_range = mtu - 20
            for j in range(new_range): # Add payload minus MTU.
                try:
                    adder += payload[j]
                except:
                    pass
            for j in adder:
                sent_packets[packet_counter][2] += j
            for fragged_pckt in adder.encode():
                frame.append(fragged_pckt)
            server_to_send = ("localhost", int(port))
            sent_packets[packet_counter][1] = int(port)
            sock.sendto(frame, server_to_send)
            payload = payload[mtu-20:]
            copy_id = packet_counter
        packet_counter += 1
        thread_fix = Thread(target = user_input)
        thread_fix.start()
        sleep(frto * 3)
        for d in range(100):
            if sent_packets[d][3] == copy_id:
                sent_packets[d][0] = 0 # IP address.
                sent_packets[d][1] = 0 # Port number.
                sent_packets[d][2] = "" # Payload.
                sent_packets[d][3] = 0 # ID of original packet.    
    else:  
        payload = payload[1:]
        payload = payload[:-1]
        frame = bytearray()
        frame.append(0b01000000) # Version + IHL.
        frame.append(0b00000000) # TOS.
        frame.append(0b11111111) # Total Length -> lower.
        frame.append(0b11111111) # Total Length -> upper.
        frame.append(0b00000000) # Identification -> upper.
        frame.append(packet_counter) # Identification -> lower.
        sent_packets[packet_counter][3] = packet_counter
        frame.append(0b00000000) # Flags -> upper.
        frame.append(0b01010101) # Flags -> lower.
        frame.append(0b11111111) # TTL.
        frame.append(0b00000000) # Protocol.
        frame.append(0b00000000) # Checksum -> upper.
        frame.append(0b01010101) # Checksum -> lower.
        sent_packets[packet_counter][0] = ip
        src = ip.split('.')
        dst = sys.argv[1]
        dst = dst.split('/')
        dst = dst[0]
        dst = dst.split('.')
        frame.append(int(dst[0])) # Add source IP.
        frame.append(int(dst[1]))
        frame.append(int(dst[2])) 
        frame.append(int(dst[3]))
        frame.append(int(src[0])) # Add destination IP.
        frame.append(int(src[1])) 
        frame.append(int(src[2])) 
        frame.append(int(src[3])) 
        for j in payload:
            sent_packets[packet_counter][2] += j
        for i in payload.encode(): # Encode payload.
            frame.append(i)
        sent_packets[packet_counter][1] = int(port)
        server_to_send = ("localhost", int(port))
        sock.sendto(frame, server_to_send)
        copy_id = packet_counter
        packet_counter += 1       
        thread_fix = Thread(target = user_input)
        thread_fix.start()
        sleep(frto * 3)
        for d in range(100):
            if sent_packets[d][3] == copy_id:
                sent_packets[d][0] = 0 # IP address.
                sent_packets[d][1] = 0 # Port number.
                sent_packets[d][2] = "" # Payload.
                sent_packets[d][3] = 0 # ID of original packet.
        
def send_to_gate(src_chk, payload):
    ip = IP_addr
    port = int(arp_table[0][1])
    thread_gate = Thread(target = build_pkt(src_chk, port, payload))
    thread_gate.start()

def in_subnet(src_chk, payload):
    for i in range(100):
        if arp_table[i][0] == src_chk: 
            port = int(arp_table[i][1])
            ip = arp_table[i][0]
    thread_gate = Thread(target = build_pkt(ip, port, payload))
    thread_gate.start()

def detect_subnet(payload):
    payload = payload.split(" ")
    src_chk = payload[1]
    payload = payload[2]
    subnet_check = False
    for i in net:
        if str(i) == src_chk:
            subnet_check = True
            break
    arp_check = False
    for i in range(100):
        if src_chk == arp_table[i][0]:
            if arp_table[i][1].isdigit():
                arp_check = True
    if arp_check and subnet_check:
        in_subnet(src_chk, payload)
    elif not arp_check and subnet_check:
        print("No ARP entry found", flush=True)
    elif not arp_check and not subnet_check:
        if IP_addr == "None":
            print("No gateway found", flush=True)
        else: 
            send_to_gate(src_chk, payload)
    else:
        print("No ARP entry found", flush=True)

def user_input():
    global prev
    global IP_kill
    global IP_addr
    global LL_addr
    global arp_table
    global mtu
    global frto
    output = input("> ")
    gw_set = "gw set"
    gw_get = "gw get"
    exit_msg = "exit"
    arp_set = "arp set"
    arp_get = "arp get"
    msg_payload = "msg"
    mtu_set = "mtu set"
    mtu_get = "mtu get"
    frto_set = "frto set"
    frto_get = "frto get"
    if not output.find(gw_set):
        IP_addr = output[7:]
    elif output == gw_get:
        print(IP_addr, flush=True)
    elif output == exit_msg:
        IP_kill = True
        os._exit(0)
    elif not output.find(arp_set):
        output = output[8:]
        output = output.split(" ", 1)
        if output[1].isdigit():
            usr_ll = output[1]
            usr_ip = output[0] 
            dup = False
            for i in range(100):
                if arp_table[i][0] == usr_ip:
                    dup = True
            if not dup:
                for i in range(100):
                    if arp_table[i][0] == 0:
                        arp_table[i][0] = usr_ip
                        arp_table[i][1] = usr_ll
                        break
            else:
                for i in range(100):
                    if arp_table[i][0] == usr_ip:
                        arp_table[i][1] = usr_ll
                        break                   
    elif not output.find(arp_get):
        output = output[8:]
        dup = False
        for i in range(100):
            if arp_table[i][0] == output:
                print(arp_table[i][1], flush=True)
                dup = True
                break
        if not dup:
            print("None", flush=True)
    elif not output.find(msg_payload):
        detect_subnet(output)
    elif not output.find(mtu_set):
        output = output[8:]
        mtu = int(output)
    elif output == mtu_get:
        print(mtu, flush=True)
    elif not output.find(frto_set):
        output = output[8:]
        frto = int(output)
    elif output == frto_get:
        print(frto, flush=True)
    user_input()
    
            
# Check system requirements.
if len(sys.argv) < 3:
    sys.exit()

# Set corresponding IP-ADDR/LL-ADDR/MTU/FRTO/IPKILL.
IP_addr = "None"
IP_cidr = sys.argv[1]
LL_addr = sys.argv[2]
mtu = 1500
frto = 5
IP_kill = False

# Determine CIDR range.
address_range = IP_cidr.split(".")
cidr = address_range[3]
cidr = cidr.split("/")
cidr = '0/' + cidr[1]
address_range = address_range[0] + '.' + address_range[1] + '.' + address_range[2] + '.' + cidr
net = ipaddress.ip_network(address_range)
prev = False

# Fragmented packets.
rest_of_packet = ""

# Declare 100 x 2 ARP lookup table.
arp_table = [[0 for x in range(2)]for y in range(100)]

# Connect to provided host.
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ("localhost", int(LL_addr))
sock.bind(server_address)

# Copy of recevied packets.
recv_packets = [[0 for x in range(5)]for y in range(100)]
for reset in range(100): # Set pre-set values.
    recv_packets[reset][0] = 0 # IP address.
    recv_packets[reset][1] = 0 # Port number.
    recv_packets[reset][2] = "" # Payload.
    recv_packets[reset][3] = 0 # Fragment flag.
    recv_packets[reset][4] = 0 # ID of original packet.
    
# Copy of sent packets.
sent_packets = [[0 for x in range(5)]for y in range(100)]
for reset in range(100): # Set pre-set values.
    sent_packets[reset][0] = 0 # IP address.
    sent_packets[reset][1] = 0 # Port number.
    sent_packets[reset][2] = "" # Payload.
    sent_packets[reset][3] = 0 # ID of original packet.
packet_counter = 0
    
single_thread = Thread(target = user_input)
single_thread.start()

# Thread for user input to command line.
# Thread for incoming packets.
# DO NOT DELETE CALL TO SLEEP.
while True: 
    if IP_kill:
        sys.exit()
    thread_udp_t = Thread(target = thread_udp)
    thread_udp_t.start()
    sleep(1)