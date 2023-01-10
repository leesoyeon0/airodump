import pcap
import time

sniffer = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)
dic = {}

for ts, pkt in sniffer:
    radioLen = int.from_bytes(pkt[2:4], byteorder='little')
    if (int.from_bytes(pkt[radioLen:radioLen+2], byteorder='little') == 0x80):
        length = int.from_bytes(pkt[radioLen+37:radioLen+38], byteorder='big')
        ssid = pkt[radioLen+38:radioLen+38+length]
        bssid = pkt[radioLen+16:radioLen+22]
        
        if ssid in dic:
        	dic[ssid] += 1
        elif ssid == b'\x00\x00\x00\x00\x00\x00\x00':
        	continue        	
        else:
        	dic[ssid] = 0
	
        if length != 0:
            print("SSID : ", end="")
            print(ssid.decode('utf-8', 'replace'))
            print("BSSID : ",end="")
            print(':'.join('%02X' % i for i in bssid))
            print("Beacons : ", end="")
            print(dic[ssid])
            print()
            time.sleep(0.5)
