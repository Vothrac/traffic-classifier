import pyshark
import os
print(pyshark.tshark.tshark.get_tshark_interfaces())
file="pyshark.pcap"
try:
    os.remove(file)
except FileNotFoundError:
    print("File not found")
cap=pyshark.LiveCapture(interface='4', output_file=file)
cap.sniff(timeout=20)
for pkt in cap:
    print(pkt)
exit(0)






