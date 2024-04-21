#!/bin/python3
import sys
import subprocess
from scapy.all import *

input_interface = "injection"
output_interface = "channel"

def xor_obfuscate(data):
    """XOR obfuscates data with a key (bytearray)"""
    ones_sequence = bytes([0xFF] * len(data))
    return bytes([b ^ k for b, k in zip(data, ones_sequence)])

def xor_deobfuscate(data):
    """XOR deobfuscates obfuscated data with the same key"""
    ones_sequence = bytes([0xFF] * len(data))
    return bytes([b ^ k for b, k in zip(data, ones_sequence)])

def setup_interface(network_addr):

    subprocess.run("ip link add dev " + input_interface + 
                   " type veth peer name " + output_interface, shell=True)
    subprocess.run("ip address add dev " + output_interface + 
                   " " + network_addr, shell=True)
    subprocess.run("ip link set dev " + input_interface + " up", shell=True)
    subprocess.run("ip link set dev " + output_interface + " up", shell=True)

    subprocess.run("ip address show dev " + output_interface, shell=True)

def remove_interface():
    subprocess.run("ip link del dev " + output_interface, shell=True)
    subprocess.run("ip link del dev " + input_interface, shell=True)

def intercept_frame(target_covert_addr):
    def intercept(frame):
        if IP in frame:
            if frame[IP].src == target_covert_addr:
                print("Intercepted frame")
                print(frame.summary())
                print(frame.show())
                # recover_frame = Ether(xor_deobfuscate(frame[IP].load))
                # print("Decoded data: " + recover_frame.summary())
                # recover_frame.show()
                # recover_frame[Ether].dst = "c2:00:8c:17:1e:3c"
                # recover_frame.show()
                #sendp(recover_frame, iface="lo")
                sendp(frame, iface="lo")
    return intercept

def inject_frame(src_addr, dst_addr):
    mac_addr = get_if_hwaddr(output_interface)

    # Inject UDP frame
    # udp_frame = Ether(src=RandMAC(), dst=mac_addr) / IP(src=src_addr, dst=dst_addr) / UDP(sport=5678, dport=6789) / "Hello, UDP\n"
    udp_frame = Ether(dst="c2:00:8c:17:1e:3c", src="a2:11:17:5f:d3:25") / IP(src=src_addr, dst=dst_addr, flags="DF") / UDP(sport=37895, dport=6789) / "Hello, UDP"
    sendp(udp_frame, iface=input_interface)

    # Inject ICMP frame
    # icmp_frame = Ether(src=RandMAC(), dst=mac_addr) / IP(src=src_addr, dst=dst_addr) / ICMP()
    # print(icmp_frame.show())
    # sendp(icmp_frame, iface=input_interface)

    # Inject TCP frame
    # tcp_frame = Ether(src=RandMAC(), dst=mac_addr) / IP(src=src_addr, dst=dst_addr) / TCP(flags="S", sport=5678, dport=6789) / "Hello, TCP"
    # sendp(tcp_frame, iface=input_interface)

# Wrap the packet in an IP packet and forward it
def wrap_and_forward(phy_interface):
    def wrap_packet(packet):
        mac_addr = get_if_hwaddr(phy_interface)
        if IP in packet:
            print("Received packet")
            print(packet.summary())

            # Forward the packet
            dst_addr = packet[IP].dst
            ip_frame = Ether(src=mac_addr, dst=RandMAC()) / IP(dst=dst_addr) / ICMP() / Raw(load=xor_obfuscate(bytes(packet)))
            print("Forwarding packet")
            print(ip_frame.summary())
            sendp(ip_frame, iface=phy_interface)
    return wrap_packet

def main():
    # Check if arguments are provided
    if len(sys.argv) < 2:
        print("Usage: python script.py <argument>")
        return

    # Get the mode and network address
    mode = sys.argv[1]

    if mode == "start":
        # Get the network address
        if len(sys.argv) < 4:
            print("Usage: python script.py start <covert_host_addr> <phy_interface>")
            return
        
        network_addr = sys.argv[2]
        phy_interface = sys.argv[3]

        print("Starting the tool...")
        # Call the setup function
        setup_interface(network_addr)

        print("Running the tool...")
        # Sniff from channel interface and forward to outside
        sniff(iface=[output_interface], prn=wrap_and_forward(phy_interface))
        
    elif mode == "stop":
        print("Stopping the tool...")
        # Call the remove function
        remove_interface()
    elif mode == "sniff":
        # Get LAN interface
        if len(sys.argv) < 4:
            print("Usage: python script.py sniff <lan_interface> <target_real_addr> <target_covert_addr>")
            return
        lan_interface = sys.argv[2]
        target_real_addr = sys.argv[3]
        target_covert_addr = sys.argv[4]

        print("Sniffing the packets...")
        sniff(iface=[lan_interface, output_interface, "lo"], prn=intercept_frame(target_covert_addr), #)
               filter='icmp or (host ' + target_real_addr + ' and udp)')
    elif mode == "inject":
        # Get the source and destination address
        if len(sys.argv) < 4:
            print("Usage: python script.py inject <src_addr> <dst_addr>")
            return
        src_addr = sys.argv[2]
        dst_addr = sys.argv[3]

        print("Injecting the packets...")
        inject_frame(src_addr, dst_addr)
    elif mode == "help":
        print("Help: python script.py <start/stop> <network_addr>")
    else:
        print("Invalid argument. Use 'help' for more information")


if __name__ == "__main__":
    main()