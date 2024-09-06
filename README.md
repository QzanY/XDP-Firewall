# XDP-Firewall
A simple eBPF XDP firewall project for Linux.\
You can add rules to or remove rules from the blacklist.

## Prerequisites

1. Install Rust(rustc 1.80.1)
2. Install bpf-linker: `cargo install bpf-linker`
3. Install Python(3.10.12)
4. Install customtkinter for GUI: `pip install customtkinter`

## Code location
The code for eBPF part is in the adv-firewall-ebpf/src folder.\
The code for the user-space part is in the adv-firewall/src folder.\
The code of the GUI is in the app.py file.

## Run

Before you run the code, you need to spesify the network interface you want to attach the program to.\
To do that you need to change the code on adv-firewall/src/main.rs line 17.
You need to write your interface instead of "enp0s10".
To check your network interfaces, you can run `ifconfig` on your terminal.

You can run the firewall with: 
```bash
./run.sh
```
You can run the GUI with:
```bash
python3 app.py
```
## How to use
### Add Rule 
With the GUI you can very simply add or remove rules. On the GUI, just click the checkbox next to the desired element and fill the entry box with the info.\
For example if you want to block all packets with source IP = 10.0.3.3, destination IP = 10.0.4.3, destination port = 8080, click the checkboxes next "Source IP", "Destination IP" and "Destination Port" and specify them in the entry boxes.\
Then click "Add" and you will see your rule on the left-hand side of the GUI. 
### Remove Rule
If you want to remove a rule, just press the "Delete" button below the rule on the left-hand side of the GUI.

## API

The user-space program listens for incoming instructions on 127.0.0.1:8080. When you add or remove a rule, the GUI application sends a message to 127.0.0.1:8080 with send_text_to_localhost function using Python's socket library.\ 
The message format is as follows:
### Adding Rule
#### ADD-index-srcmac-dstmac-ethertype-srcip-dstip-protocol-srcport-dstport
index: The index of the rule on the array of rules. Check Windox.add_rule function for how indexing works.\
srcmac: The source MAC address of the packet.\
dstmac: The destination MAC address of the packet.\
ethertype: The etherType of the packet. Currently you can only write IPV4 and IPV6 protocols. Other protocols are not supported.\
srcip: The source of IP address of the packet.\
dstip: The destination IP address of the packet.\
protocol: The L4 protocol of the packet. Currently only TCP,UDP and ICMP protocols are supported.\
srcport: The source port of the packet.\
dstport: The destination port of the packet.

### Removing Rule
#### DEL-index
index: The index of the rule on the array of rules. Check Window.add_rule function for how indexing works.
