#!/bin/python3
import sys
import subprocess
import threading
from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

input_interface = "injection"
output_interface = "channel"
encryption_key = b"1234567890123456"

def encrypt(data, key):
    """Encrypts data using AES encryption with a given key"""
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return encrypted_data

def decrypt(data, key):
    """Decrypts data using AES decryption with a given key"""
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
    return decrypted_data

# XOR obfuscation and deobfuscation functions by XORing the data with a sequence of 1s with the same length
def obfuscate(data):
    """Obfuscates data by XORing it with a sequence of 1s with the same length"""
    obfuscated_data = bytes([byte ^ 0xFF for byte in data])
    return obfuscated_data

def deobfuscate(data):
    """Deobfuscates data by XORing it with a sequence of 1s with the same length"""
    deobfuscated_data = bytes([byte ^ 0xFF for byte in data])
    return deobfuscated_data

# Setup the interface
def setup_interface(network_addr):
    subprocess.run("ip link add dev " + input_interface + 
                   " type veth peer name " + output_interface, shell=True)
    subprocess.run("ip address add dev " + output_interface + 
                   " " + network_addr, shell=True)
    subprocess.run("ip link set dev " + input_interface + " up", shell=True)
    subprocess.run("ip link set dev " + output_interface + " up", shell=True)

    subprocess.run("ip address show dev " + output_interface, shell=True)

# Remove the interface
def remove_interface():
    subprocess.run("ip link del dev " + output_interface, shell=True)
    subprocess.run("ip link del dev " + input_interface, shell=True)

# Wrap the packet in an IP packet and forward it
def wrap_and_forward(protected_mode, target_real_addr, gateway_iface, isSilentMode=False):
    def wrap_packet(packet):
        # Get the host's MAC address
        mac_addr = get_if_hwaddr(gateway_iface)
        src_ip = get_if_addr(gateway_iface)
        src_covert_ip = get_if_addr(output_interface)
        if IP in packet:

            if packet[IP].dst == src_covert_ip:
                return

            if not isSilentMode:
                print("Received packet")
                print(packet.summary())

            # Wrap the packet
            if protected_mode == "0":
                ip_frame = Ether(src=mac_addr) / IP(src=src_ip, dst=target_real_addr) / ICMP() / Raw(load=obfuscate(bytes(packet)))
            elif protected_mode == "1":
                ip_frame = Ether(src=mac_addr) / IP(src=src_ip, dst=target_real_addr) / ICMP() / Raw(load=encrypt(bytes(packet), encryption_key))

            if not isSilentMode:
                print("Wrapped packet: ")
                print(ip_frame.summary())

            # Forward the packet
                print("Forwarding packet ...")
                print(ip_frame.summary())

            # Send the packet to the target through the gateway
            sendp(ip_frame, iface=gateway_iface, verbose=not isSilentMode)
    return wrap_packet

# Intercept the frame, recover the data and send it to the channel
def intercept_frame(protected_mode, target_real_addr, target_covert_addr, isSilentMode=False):
    def intercept(frame):
        if IP in frame:
            # Check if the frame is sent to the target's covert address
            if frame[IP].src == target_real_addr:
                if not isSilentMode:
                    print("Intercepted frame")
                    print(frame.summary())

                # Recover the data
                if protected_mode == "0":
                    recover_frame = Ether(deobfuscate(frame[IP].load))
                elif protected_mode == "1":
                    recover_frame = Ether(decrypt(frame[IP].load, encryption_key))

                if not isSilentMode:
                    print("Decoded data: ")
                    recover_frame.show()

                # Send the frame to the channel
                if recover_frame[IP].src == target_covert_addr:
                    sendp(recover_frame, iface=output_interface, verbose=not isSilentMode)

                #sendp(recover_frame, iface="lo") #Send to loopback interface for testing with socat
    return intercept

# Inject the test frames
def inject_frame(src_addr, dst_addr):
    # Channel veth interface's MAC address
    mac_addr = get_if_hwaddr(output_interface)

    # UDP and TCP testing frames
    udp_frame = Ether(src=RandMAC(), dst=mac_addr) / IP(src=src_addr, dst=dst_addr) / UDP(sport=5678, dport=6789) / "Hello, UDP\n"
    tcp_frame = Ether(src=RandMAC(), dst=mac_addr) / IP(src=src_addr, dst=dst_addr) / TCP(flags="S", sport=5678, dport=6789) / "Hello, TCP\n"

    # UDP and TCP testing frames for testing with socat
    # udp_frame = Ether(dst="00:00:00:00:00:00", src="00:00:00:00:00:00") / IP(src=src_addr, dst=dst_addr, flags="DF") / UDP(sport=37895, dport=6789) / "Hello, UDP\n"
    # tcp_frame = Ether(dst="00:00:00:00:00:00", src="00:00:00:00:00:00") / IP(src=src_addr, dst=dst_addr, flags="DF") / TCP(flags="S", sport=5678, dport=6789, options=[('MSS', 65495), ('SAckOK', b''), ('Timestamp', (0, 0)), ('WScale', 7)])    

    # Send the frames
    sendp(udp_frame, iface=input_interface)
    sendp(tcp_frame, iface=input_interface)

# Send messages in chat mode
def chat_send_messages(protocol, host_covert_addr, target_covert_addr):
    print("Welcome to the Chat App!")
    print("Type your messages below:\n")
    while True:
        message = input(":> ")
        if protocol == "udp":
            udp_frame = Ether(src=RandMAC(), dst=RandMAC()) / IP(src=host_covert_addr, dst=target_covert_addr) / UDP(sport=5678, dport=6789) / message
            sendp(udp_frame, iface=input_interface, verbose=False)
        elif protocol == "tcp": # Need improvement
            tcp_frame = Ether(src=RandMAC(), dst=RandMAC()) / IP(src=host_covert_addr, dst=target_covert_addr) / TCP(flags="S", sport=5678, dport=6789) / message
            sendp(tcp_frame, iface=input_interface, verbose=False)

# Wrap and forward your packets
def chat_wrap_and_forward(protected_mode, target_real_addr, gateway_iface):
    # Sniff from channel interface and forward them outside
    sniff(iface=[output_interface], prn=wrap_and_forward(protected_mode, target_real_addr, gateway_iface, isSilentMode=True),
            filter='udp or tcp')

# Intercept the incoming frames
def chat_intercept_incoming_frame(protected_mode, target_real_addr, target_covert_addr, gateway_iface):
    # Sniff from the gateway interface and unwrap the packets
    sniff(iface=[gateway_iface, output_interface], prn=intercept_frame(protected_mode, target_real_addr, target_covert_addr, isSilentMode=True),
            filter='icmp')
    
def chat_get_messages(host_covert_addr):
    # Sniff from the gateway interface and unwrap the packets
    sniff(iface=[output_interface], prn=sniff_channel_content(host_covert_addr),
            filter='udp or tcp')
    
def sniff_channel_content(host_covert_addr):
    def sniff_content(packet):
        if IP in packet and packet[IP].dst == host_covert_addr:
                print(f"Received message from {packet[IP].src}: {packet[IP].load.decode(errors='ignore')}\n:> ", end="")
    return sniff_content

# Check if the interfaces are set up
def check_if_setup():
    # Check if the interfaces are set up
    if subprocess.run("ip link show dev " + input_interface, shell=True).returncode != 0:
        print("Error: Interfaces are not set up. Please run 'setup' first")
        return False
    return True

# Print invalid command
def print_invalid_command():
    print("Invalid command. Use 'help' for more information")

def main():
    # Check if arguments are provided
    if len(sys.argv) < 2:
        print("Usage: python script.py <argument>")
        return

    # Get the mode and network address
    mode = sys.argv[1]

    # Tool's manual
    if mode == "help":
        print("WhisperNet 1.0 by the NGUYENs - a covert channel tool using ICMP protocol")
        print("Usage: python whisper.py [option] [arguments]")
        print("Options:")
        print("      setup <network_addr>")
        print("        - Setup the veth interfaces")
        print("      remove")
        print("        - Remove the veth interfaces")
        print("      sendmode <protected_mode> <target_real_addr> <gateway_iface>")
        print("        - Sniff packets on host, wrap and forward them to the target through the gateway. Should be used with recvmode on the target")
        print("      recvmode <protected_mode> <gateway_iface> <host_real_addr> <host_covert_addr>")
        print("        - Sniff packets on the target, unwrap and send them to the channel. Should be used with sendmode on the host")
        print("      inject <src_addr> <dst_addr>")
        print("        - Inject the test packets (Hidden ip addresses)")
        print("      chat <protocol> <protected_mode> <gateway_iface> <host_covert_addr> <target_covert_addr> <target_real_addr>")
        print("        - Chat mode using UDP or TCP protocol")

        print("Protected mode:")
        print("      - 0: XOR obfuscation")
        print("      - 1: AES encryption")

    # Setting up the veth interfaces
    elif mode == "setup":
        # Get the network address
        if len(sys.argv) < 3:
            print_invalid_command()
            return
        
        # The host's covert channel address
        network_addr = sys.argv[2]

        print("Setting up the tool...")
        setup_interface(network_addr)

    # Removing the veth interfaces
    elif mode == "remove":
        print("Stopping the tool...")
        remove_interface()

    # To illustrate the wraping and forwarding of packets on the host, should be along with the recvmode on the target
    elif mode == "sendmode":
        # Get the network address
        if len(sys.argv) < 5:
            print_invalid_command()
            return
        
        # Procted mode
        protected_mode = sys.argv[2]
        # The target LAN address
        target_real_addr = sys.argv[3]
        # The host's gateway interface
        gateway_iface = sys.argv[4]
        
        check_if_setup()

        # Sniff from channel interface and forward them outside
        print("Waiting for packets...")
        sniff(iface=[output_interface], prn=wrap_and_forward(protected_mode, target_real_addr, gateway_iface))
    
    # Sniff the packets on the target, unwrap and send them to the channel. Should be used with sendmode on the host
    elif mode == "recvmode":
        if len(sys.argv) < 4:
            print_invalid_command()
            return
        
        # Procted mode
        protected_mode = sys.argv[2]
        # The gateway interface
        gateway_iface = sys.argv[3]
        # The host's real address (address of the host/sender on the LAN)
        host_real_addr = sys.argv[4]
        # The host's covert channel address (sender's covert address)
        host_covert_addr = sys.argv[5]
        
        check_if_setup()

        # Sniff from the gateway interface and unwrap the packets
        print("Sniffing the packets...")
        sniff(iface=[gateway_iface, output_interface], prn=intercept_frame(protected_mode, host_real_addr, host_covert_addr),
               filter='icmp or (host ' + host_real_addr + ' and udp)')
        
    # Inject test packets
    elif mode == "inject":
        # Get the source and destination address
        if len(sys.argv) < 4:
            print_invalid_command()
            return
        
        # The source and destination address (covert channel address)
        src_addr = sys.argv[2]
        dst_addr = sys.argv[3]

        check_if_setup()

        print("Injecting the packets...")
        inject_frame(src_addr, dst_addr)

    # Chat mode
    elif mode == "chat":
        if len(sys.argv) < 8:
            print_invalid_command()
            return
        
        # Chat mode using UDP or TCP protocol
        protocol = sys.argv[2]
        # Protected mode
        protected_mode = sys.argv[3]
        # The gateway interface
        gateway_iface = sys.argv[4]
        # The host's covert channel address
        host_covert_addr = sys.argv[5]
        # The target's covert channel address
        target_covert_addr = sys.argv[6]
        # The target's real address
        target_real_addr = sys.argv[7]

        print("Chat mode is starting...")
        
        if check_if_setup():
            # Start thread to sniff and wrap your packets
            wrap_thread = threading.Thread(target=chat_wrap_and_forward, args=(protected_mode, target_real_addr, gateway_iface))
            wrap_thread.start()

            # Start thread to sniff and unwrap the packets from the target
            intercept_thread = threading.Thread(target=chat_intercept_incoming_frame, args=(protected_mode, target_real_addr, target_covert_addr, gateway_iface))
            intercept_thread.start()

            # Start thread to sniff the channel content
            get_messages_thread = threading.Thread(target=chat_get_messages, args=(host_covert_addr,))
            get_messages_thread.start()

            # Start sending messages
            chat_send_messages(protocol, host_covert_addr, target_covert_addr)

    # Invalid command
    else:
        print_invalid_command()


if __name__ == "__main__":
    main()