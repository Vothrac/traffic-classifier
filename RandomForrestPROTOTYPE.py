import pandas as pd
import numpy as np
from scapy.all import *
import pyshark
import os

########################################################################################################################
####                                          Disclaimer: first Python project                                      ####
########################################################################################################################
pysharkas=pyshark.FileCapture('twitteris1.pcap')
packets=rdpcap('twitteris1.pcap')  #pcap failas
ipadress='10.0.2.15'  #IP adresas kompiuterio, iš kuri capturinta
website=0             #Svetainė, kurioj buvo capturinta(naudoju iškart numerius)
upcounter = 0         #Upstream packetu counteris
downcounter=0         #Downstream packetu counteris
packetcount=len(packets) #visu packetu counteris
intarvu=[]
intarvd=[]
intarv= []             #intervalai laiko
intarvup=[]            #Upstream intervalai
intarvdown=[]          #Downstream intervalai
payloaddown=[]         #L4 Payload dowstream
payloadup=[]           #L4 payload upstream
payload=[]             #L4 payload apskritai
time=0                 #Visas laikas
timeup=0               #Upstream laikas
timedown=0             #Downstream laikas
#2-3 punktai
#packetcount=packetlength(packets)

sesija=packets[TCP].sessions()

for packet in packets:
        if packet['IP'].src==ipadress:
                upcounter+=1
        if packet['IP'].dst==ipadress:
                downcounter+=1
#4 punktas, mediana
#packetas[i+1]-packetas[i], skaičiuojamas intervalas, kartais gaunasi minusinis, laikas UNIX, gaunasi su -e, nežinau ar veikia korektiškai Random foreste
for i in range (0, packetcount-1):
        intarv.append(packets[i+1].time-packets[i].time)
intarv.sort()         #Rikiuojami intervalai, nes mediana skaičiuojasi iš surikiuotų duomenų
half=int(round(len(intarv)/2))   #Vidurys
median=intarv[half]              #mediana
#5punktas
maxintarv=intarv[len(intarv)-1]   #Pats didžiausias intervalas
#6punktas
minintarv=intarv[0]              #Pats mažiausias intervalas
#7punktas pasiruosimas
for i in range (0, packetcount):
        if(packets[i]['IP'].src==ipadress):
            intarvu.append(packets[i])
              #  intarvup.append(packets[i+1].time - packets[i].time)
for i in range(0, packetcount):
        if(packets[i]['IP'].dst==ipadress):
            intarvd.append(packets[i])
                #intarvdown.append(packets[i+1].time - packets[i].time)
#toliau reikia susiskaičiuot intervalus ir ieškot 7... punktų
for i in range(0, len(intarvu)-1):
        intarvup.append(intarvu[i+1].time-intarvu[i].time)
for i in range(0, len(intarvd)-1):
        intarvdown.append((intarvd[i+1].time-intarvd[i].time))
intarvup.sort()
intarvdown.sort()

#7 punktas
half=int(round(len(intarvup)/2))
upstreamintarvmedian=intarvup[half]
#8 punktas
upstreamintarvmin=intarvup[0]
#9 punktas
upstreamintarvmax=intarvup[len(intarvup)-1]
#10 punktas
half=int(round(len(intarvdown)/2))
print(half)
print(len(intarvdown))
downstreamintarvmedian=intarvdown[half]
#11 punktas
downstreamintarvmin=intarvdown[0]
#12punktas
downstreaintarvmax=intarvdown[len(intarvdown)-1]
#13-24 punkto pasiruošimas
for packet in packets:
        if TCP in packet:
                payload.append(len(packet[TCP].payload))
                if packet['IP'].src == ipadress:
                        payloadup.append((len(packet[TCP].payload)))
                if packet['IP'].dst == ipadress:
                        payloaddown.append((len(packet[TCP].payload)))
        if UDP in packet:
                payload.append(len(packet[UDP].payload))
                if packet['IP'].src == ipadress:
                    payloadup.append((len(packet[UDP].payload)))
                if packet['IP'].dst == ipadress:
                    payloaddown.append((len(packet[UDP].payload)))

payload.sort()
payloaddown.sort()
payloadup.sort()
half=int(round(len(payload)/2))
medianpayload=payload[half]
maximumpayload=payload[len(payload)-1]
minimumpayload=payload[0]                            #0?????
maxminusmin=maximumpayload-minimumpayload            #max-0=max!!!!!

half=int(round(len(payloadup)/2))
medianuppayload=payloadup[half]
maxuppayload=payloadup[len(payloadup)-1]
minuppayload=payloadup[0]                            #0?????
upmaxminusmin=maxuppayload-minuppayload              #max-0=max!!!!!

half=int(round(len(payloaddown)/2))
medianpayloaddown=payloaddown[half]  # BĖDA, TCP DYDIS 0. Reikia udp, bet jo downstream nera
maxdownpayload=payloaddown[len(payloaddown)-1]
mindownpayload=payloaddown[0]
downmaxminusmin=maxdownpayload-mindownpayload

#25-27 punktai
for packet in packets:
        time+=packet.time
        if packet['IP'].src==ipadress:
                timeup+=packet.time
        if packet['IP'].dst==ipadress:
                timedown+=packet.time
wholetime=0
temporarytime=0
changes=0
temporarychanges=0
wholetimeup=0
wholetimedown=0
#28-29 punktas
for i in range(0, packetcount-1):
        if(packets[i]['IP'].src==packets[i+1]['IP'].src):
                temporarychanges+=1
                temporarytime+=packets[i].time
        else:
                temporarychanges=0
                temporarytime=0
        if temporarychanges==3:
                changes+=1
                wholetime+=time
#30 punktas
for i in range(0, packetcount-1):
    if packets[i]['IP'].src == ipadress:
        if (packets[i]['IP'].src == packets[i + 1]['IP'].src):
            temporarychanges += 1
            temporarytime += packets[i].time
        else:
            temporarychanges = 0
            temporarytime = 0
        if temporarychanges == 3:
            wholetimeup += time
#31 punktas
for i in range(0, packetcount-1):
    if packets[i]['IP'].dst == ipadress:
        if (packets[i]['IP'].src == packets[i + 1]['IP'].src):
            temporarychanges += 1
            temporarytime += packets[i].time
        else:
            temporarychanges = 0
            temporarytime = 0
        if temporarychanges == 3:
            wholetimedown += time
print(upcounter)
print(downcounter)
print(median)
print(maxintarv)
print(minintarv)
print(upstreamintarvmax)
print("{} {}".format(upstreamintarvmedian, "Median"))
print(upstreamintarvmin)
print(downstreaintarvmax)
print(downstreamintarvmedian)
print(downstreamintarvmin)
print(medianpayload)
print(maximumpayload)
print(minimumpayload)
print(maxminusmin)
print("median {}   max {}    min {}    max-min {}    ".format(medianuppayload, maxuppayload, minuppayload, upmaxminusmin))
print("median {}   max {}    min {}    max-min {}    ".format(medianpayloaddown, maxdownpayload, mindownpayload, downmaxminusmin))
print("time {} uptime {} downtime {}".format(time, timeup, timedown))
print("changes: {} time: {}".format(changes, wholetime))
print("UPSTREAM time: {}".format(wholetimeup))
print("DOWNSTREAM time: {}".format(wholetimedown))

o=0
for k, v in sesija.items():
        for p in v:
            print(p)




#ruošiamasi formuot pandas data frame
raw_data={'packet_cnt': [packetcount],
          'packet_cnt_up':[upcounter],
          'packet_cnt_down': [downcounter],
          'intarv_time_med': [median],
          'intarv_time_max': [maxintarv],
          'intarv_time_min': [minintarv],
          'intarv_time_med_up': [upstreamintarvmedian],
          'intarv_time_max_up': [upstreamintarvmax],
          'intarv_time_min_up': [upstreamintarvmin],
          'intarv_time_med_down': [downstreamintarvmedian],
          'intarv_time_max_down': [downstreaintarvmax],
          'intarv_time_min_down': [downstreamintarvmin],
          'bytes_payload_l4_med': [medianpayload],
          'bytes_payload_l4_max': [maximumpayload],
          'bytes_payload_l4_min': [minimumpayload],
          'bytes_payload_range': [maxminusmin],
          'bytes_payload_l4_med_up': [medianuppayload],
          'bytes_payload_l4_max_up': [maxuppayload],
          'bytes_payload_l4_min_up': [minuppayload],
          'bytes_payload_range_up': [upmaxminusmin],
          'bytes_payload_l4_med_down': [medianpayloaddown],
          'bytes_payload_l4_max_down': [maxdownpayload],
          'bytes_payload_l4_min_down': [mindownpayload],
          'bytes_payload_range_down': [downmaxminusmin],
          'duration_flow': [time],
          'duration_flow_up': [timeup],
          'duration_flow_down': [timedown],
          'changes_bulktrans_mode': [changes],
          'duration_bulkmode': [wholetime],
          'duration_bulkmode_up': [wholetimeup],
          'duration_bulkmode_down': [wholetimedown],
          'website': [website]}
#Formuojamas pandas dataFrame
df=pd.DataFrame(raw_data, columns=['packet_cnt', 'packet_cnt_up', 'packet_cnt_down', 'intarv_time_med','intarv_time_max',
                                  'intarv_time_min', 'intarv_time_med_up', 'intarv_time_max_up', 'intarv_time_min_up',
                                  'intarv_time_med_down', 'intarv_time_max_down', 'intarv_time_min_down',
                                  'bytes_payload_l4_med', 'bytes_payload_l4_max', 'bytes_payload_l4_min', 'bytes_payload_range',
                                  'bytes_payload_l4_med_up', 'bytes_payload_l4_max_up', 'bytes_payload_l4_min_up','bytes_payload_range_up', 'bytes_payload_l4_med_down', 'bytes_payload_l4_max_down',
                                  'bytes_payload_l4_min_down', 'bytes_payload_range_down', 'duration_flow', 'duration_flow_up',
                                  'duration_flow_down', 'changes_bulktrans_mode', 'duration_bulkmode',
                                  'duration_bulkmode_up', 'duration_bulkmode_down', 'website'])
try:
        os.remove("testavimas.csv")
except:
    print("File not found")

#Išvedama į .csv failą
df.to_csv("testavimas.csv", encoding='utf-8', index=False)


