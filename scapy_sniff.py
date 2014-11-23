#! /usr/local/bin/python
from scapy.all import *
def multicast_monitor_callback(pkt):

#	print "%s" %(pkt[Ether].src)
#	print "%s" %(pkt[Ether].dst)
#	print "%s" %(pkt[Ether].type)
#	print "%s" %(pkt[IP].version)
#	print "%s" %(pkt[IP].ihl)
#	print "%s" %(pkt[IP].tos)
#	print "%s" %(pkt[IP].len)
#	print "%s" %(pkt[IP].id)
#	print "%s" %(pkt[IP].flags)
#	print "%s" %(pkt[IP].frag)
#	print "%s" %(pkt[IP].ttl)
#	print "%s" %(pkt[IP].proto)
#	print "%s" %(pkt[IP].chksum)
#	print "%s" %(pkt[IP].src)
#	print "%s" %(pkt[IP].dst)
#	print "%s" %(pkt[UDP].sport)
#	print "%s" %(pkt[UDP].dport)
#	print "%s" %(pkt[UDP].len)
#	print "%s" %(pkt[UDP].chksum)
#	print "%s" %(pkt[Raw].load)
#	print "%s" %(pkt[Padding].load)
#	print pkt.show

        #get data from the packet
        #h_size = eth_length + iph_length + udph_length
        #data = packet[h_size:]

#	h_size = 14 + (pkt[IP].ihl) * 4 + 8
#       data = pkt[Raw].load[h_size:]

	notopen=1

	if (pkt[UDP] && pkt[UDP].dport==2068):

		frame_n=ord(pkt[Raw].load[0])*256+ord(pkt[Raw].load[1])
              	part=ord(pkt[Raw].load[2])*256+ord(pkt[Raw].load[3])
              	if (part==0) : # & (notopen==1) :
#			print "frame",frame_n,"part",part, "len",len(pkt[Raw].load)
#  		        sys.stdout.write(pkt[Raw].load.encode('hex'))
#			sys.stdout.write(pkt[Padding].load.encode('hex')) # This IS the missing data

			f = open('files/'+str(frame_n)+"_"+str(part).zfill(3)+'.jpg', 'w')
#                	fname = str(frame_n)+"_"+str(part).zfill(3)+'.jpg'

                	print "\n--myboundary\nContent-Type: image/jpeg\n"
                	notopen=0
              	if notopen==0:
                	sys.stdout.write(pkt[Raw].load[4:] + pkt[Padding].load)
			f.write(pkt[Raw].load[4:] + pkt[Padding].load)

sniff(iface="en5", prn=multicast_monitor_callback, filter="", store=0)
