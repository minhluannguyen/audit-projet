# WhisperNet 1.0
### By The NGUYENs

WhisperNet is a covert channel tool that utilizes the ICMP protocol to securely transmit data across a network. Designed for environments where security and stealth are critical, WhisperNet supports obfuscation and encryption mechanisms to protect sensitive data in transit.

## Main Features
- **ICMP-based covert data transfer**: Uses ICMP packets for discreet communication.
- **Flexible security options**: Supports XOR obfuscation and AES encryption.
- **Chat functionality over UDP or TCP**: Allows secure chat sessions over covert channels.

---

## Installation & Setup

### Prerequisites
- Python 3.x
- Administrative privileges to set up and remove virtual Ethernet (veth) interfaces.

### Installation
1. Clone this repository.
2. Install required dependencies.

```bash
git clone https://github.com/your-repo/whispernet.git
cd whispernet
pip install -r requirements.txt
```

## Network Topology

![Network Topology](/netlab/graph.png)

## Usage Instructions

### Setting Up the Network

1. **Build the Network Architecture**:
```sh
$ bash build_architecture
```

2. **Clean the Network Setup**:
```sh
$ bash clean
```

### Running the Tool

1. **Command syntax**:
```sh
$ python tool.py [option] [arguments]
```

2. **Options**:
- ***setup <network_addr>***: Set up the network.

```sh
[h1]
$ python tool.py setup 10.81.81.1/24

[h2]
$ python tool.py setup 10.81.81.2/24
```

- ***remove***: Remove the network setup.

```sh
$ python tool.py remove
```

- ***sendmode <protected_mode> <target_real_addr> <gateway_iface>***: Sniff packets on host, wrap and forward them to the target through the gateway. Should be used with *recvmode* on the target.

```sh
[h1] 
$ python tool.py sendmode 1 192.168.20.1 h1-eth0
```

- ***recvmode <protected_mode> <gateway_iface> <host_real_addr> <host_covert_addr>***: Sniff packets on the target, unwrap and send them to the channel. Should be used with *sendmode* on the host.

```sh
[h2] 
$ python tool.py recvmode 1 h2-eth0 192.168.10.1 10.87.87.2
```

- ***inject <src_addr> <dst_addr>***: Inject the test packets (Hidden ip addresses)

```sh
[h1] 
$ python tool.py inject 10.87.87.1 10.87.87.2
```

- ***chat <protocol> <protected_mode> <gateway_iface> <host_covert_addr> <target_covert_addr> <target_real_addr>***: Start a chat session with the target with UDP or TCP protocol.

```sh
[h1]
$ python tool.py chat udp 0 h1-eth0 10.87.87.1 10.87.87.2 192.168.20.1

[h2]
$ python tool.py chat udp 0 h2-eth0 10.87.87.2 10.87.87.1 192.168.10.1
```

- ***Protected Mode***:
    - **0**: XOR obfuscation.
    - **1**: AES encryption.

    