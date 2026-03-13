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

---

## Security Notes

### CVE-2024-2004 / HackerOne report #2384833 — curl `--proto` disabled-protocol bypass

**Severity:** Low  
**Affected versions:** curl 7.85.0 – 8.6.0  
**Fixed in:** curl 8.7.1 (2024-03-27)  
**Reference:** https://curl.se/docs/CVE-2024-2004.html

#### Description

curl's `--proto` flag is meant to restrict which protocols are allowed.  
Passing `-all` should forbid every protocol so that no transfer can happen.

On affected versions, a `--proto` string that:
1. starts with `-all` (remove all protocols), **and**
2. only removes individual protocols after that (never adds any back)

…silently drops the restriction, allowing **all** protocols.  
This means data can be sent over an unencrypted channel even when the caller
explicitly intends to block all transfers.

#### Steps to reproduce

On a vulnerable system (curl 7.85.0 – 8.6.0) the following commands should
return an error (`curl: (1) Protocol "http" not supported or disabled in libcurl`)
but instead **succeed**:

```sh
# Should fail — but doesn't on vulnerable versions
curl -Ivs --proto -all                    http://curl.se
curl -Ivs --proto -all,-http              http://curl.se
curl -Ivs --proto -all,-ftp,-smtp,-pop3   http://curl.se
```

Compare with a correctly behaving scenario (these always block HTTP):

```sh
curl -Ivs --proto -http          http://curl.se   # blocks http
curl -Ivs --proto -all,https     http://curl.se   # blocks http (only https allowed)
```

#### Automated reproduction

Two helper scripts are included:

```sh
# Shell script (prints version info + runs live tests)
bash reproduce_cve_2024_2004.sh

# Python script (version check + live behavioural tests)
python3 check_curl_cve_2024_2004.py
```

#### Remediation

Upgrade curl to **8.7.1 or later**: https://curl.se/download.html

    