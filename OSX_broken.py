import time
import struct
import socket
import sys

def main():

    # Look up multicast group address in name server and find out IP version
    addrinfo = socket.getaddrinfo("226.2.2.2", None)[0]
    print addrinfo[0]

    # Create a socket
    s = socket.socket(addrinfo[0], socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 2068))

    group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
    if addrinfo[0] == socket.AF_INET: # IPv4
	mreq = socket.inet_aton('226.2.2.2')+socket.inet_aton('192.168.168.123')
	s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    while True:
        data, sender = s.recvfrom(65565)
        while data[-1:] == '\0': data = data[:-1] # Strip trailing \0's
#        print (str(sender) + '  ' + repr(data))
	notopen=1
	frame_n=ord(data[0])*256+ord(data[1])
	part=ord(data[2])*256+ord(data[3])
	if (part==0) : # & (notopen==1) 
            f = open('files/'+str(frame_n)+"_"+str(part).zfill(3)+'.jpg', 'w')
            fname = str(frame_n)+"_"+str(part).zfill(3)+'.jpg'

# jpeginfo -c files/2706_000.jpg 
# files/2706_000.jpg 1920 x 1080 24bit JFIF  N    1012  Premature end of JPEG file  [WARNING]

	    print "\n--myboundary\nContent-Type: image/jpeg\n"
	    notopen=0
	if notopen==0:
 	    f.write(data[4:])
	    sys.stdout.write(data[4:])

if __name__ == '__main__':
    main()

