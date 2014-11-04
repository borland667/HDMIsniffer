# Hat tip to http://danman.eu/blog/reverse-engineering-lenkeng-hdmi-over-ip-extender/

require 'socket'
require 'ipaddr'

#  sudo tcpdump -xX -vvv -i en0 host 192.168.168.56 or host 192.168.168.55 and less 1016
# This capture only shows a single ARP packet FROM the RX, NOTHING else... 

MULTICAST_ADDR = "226.2.2.2"
PORT = 2068
SENDERIP = 192.168.168.55
CONTROLPORT = 48689
ip =  IPAddr.new(MULTICAST_ADDR).hton + IPAddr.new("0.0.0.0").hton
sock = UDPSocket.new
sock.setsockopt(Socket::IPPROTO_IP, Socket::IP_ADD_MEMBERSHIP, ip)
sock.bind(Socket::INADDR_ANY, PORT)

begin
  socket = UDPSocket.open
  socket.send("\x54\x46\x36\x7A\x60\x02\x00\x00\x00\x00\x00\x03\x03\x01\x00\x26\x00\x00\x00\x00\x02\x34\xC2", 0, SENDERIP, CONTROLPORT)
  puts "sent control message"
ensure
  socket.close 
  puts "closed the control socket"
end

loop do
  msg, info = sock.recvfrom(1024)
#  puts "MSG: #{msg} from #{info[2]} (#{info[3]})/#{info[1]} len #{msg.size}" 
  puts "MSG: len #{msg.size}" 
end

# These packets from TX (192.168.168.55) take the RX (192.168.168.56) out of the "Searching TX" state... they seem to be a heartbeat of some sort. 
# Once the RX sees them it displays "Check TX's input signal" if there is no input signal on the HDMI port. 

#21:11:01.215524 IP (tos 0xfc, ttl 64, id 23358, offset 0, flags [none], proto UDP (17), length 540)
#192.168.168.55.48689 > 255.255.255.255.48689: [udp sum ok] UDP, length 512
#0x0000:  45fc 021c 5b3e 0000 4011 b3b7 c0a8 a837  E...[>..@......7
#0x0010:  ffff ffff be31 be31 0208 34a4 5446 367a  .....1.1..4.TF6z
#0x0020:  6301 0000 3e5b 0003 0303 0024 0000 0000  c...>[.....$....
#0x0030:  0000 0000 0000 0010 0000 0000 0000 0000  ................
#0x0040:  0000 0078 0164 aeb8 0001 0000 0000 020a  ...x.d..........
#0x0050:  0000 0000 0000 0000 0000 0000 0000 0000  ................
#0x0060:  0000 0000 0000 0000 0000 0000 0000 0000  ................
#0x0070:  0000 0000 0000 0000 0000 0000 0000 0000  ................
#0x0080:  0000 0000 0000 0000 0000 0000 0000 0000  ................
#...
#0x0210:  0000 0000 0000 0000 0000 0000            ............

#     192.168.168.55.48689 > 255.255.255.255.48689: [udp sum ok] UDP, length 512
#0x0000:  45fc 021c 5b3d 0000 4011 b3b8 c0a8 a837  E...[=..@......7
#0x0010:  ffff ffff be31 be31 0208 398d 5446 367a  .....1.1..9.TF6z
#0x0020:  6301 0000 3d5b 0003 0303 0024 0000 0000  c...=[.....$....
#0x0030:  0000 0000 0000 0010 0000 0000 0000 0000  ................
#0x0040:  0000 0078 0164 aacf 0001 0000 0000 020a  ...x.d..........
#0x0050:  0000 0000 0000 0000 0000 0000 0000 0000  ................
#...
#0x0210:  0000 0000 0000 0000 0000 0000            ............

# Arp after the RX node comes up... 

# 21:15:29.572743 ARP, Ethernet (len 6), IPv4 (len 4), Request who-has 192.168.168.55 tell 192.168.168.56, length 46
# 0x0000:  0001 0800 0604 0001 000b 7800 6002 c0a8  ..........x.`...
# 0x0010:  a838 0000 0000 0000 c0a8 a837 0000 0000  .8.........7....
# 0x0020:  0000 0000 0000 0000 0000 0000 0000       ..............

# Traffic on port 2067 AFTER the Arp...

# 21:15:29.630847 IP (tos 0x40, ttl 128, id 9006, offset 0, flags [none], proto UDP (17), length 48)
# 192.168.168.55.dlswpn > 226.2.2.2.dlswpn: [no cksum] UDP, length 20
# 0x0000:  4540 0030 232e 0000 8011 ca6a c0a8 a837  E@.0#......j...7
# 0x0010:  e202 0202 0813 0813 001c 0000 0000 0000  ................
# 0x0020:  88e3 0000 0000 0000 0000 0000 0000 0000  ................
# 0x0030:  00                             

# Data starts flowing to port 2068 in 1016 length packets... the *first* has a JFIF header...

#21:15:29.631003 IP (tos 0x40, ttl 128, id 9006, offset 0, flags [none], proto UDP (17), length 1044)
#192.168.168.55.avauthsrvprtcl > 226.2.2.2.avauthsrvprtcl: [no cksum] UDP, length 1016
#0x0000:  4540 0414 232e 0000 8011 c686 c0a8 a837  E@..#..........7
#0x0010:  e202 0202 0814 0814 0400 0000 88e3 0000  ................
#0x0020:  ffd8 ffe0 0010 4a46 4946 0001 0100 0001  ......JFIF......
#0x0030:  0001 0000 ffdb 0084 0003 0304 0606 090a  ................
#0x0040:  0d04 0405 0606 0b0b 0806 0405 0709 0b0f  ................
#0x0050:  0b06 0506 070b 1210 0c08 0509 0e0f 1615  ................
#0x0060:  130b 070c 0e11 151c 1117 0c14 161a 1e1e  ................
#0x0070:  1922 1314 1923 1f1a 2101 0405 060c 1919  ."...#..!.......
#0x0080:  1919 0505 0711 1919 1919 0607 0e19 1919  ................
#0x0090:  1919 0c11 1919 1919 1919 1919 1919 1919  ................
#0x00a0:  1919 1919 1919 1919 1919 1919 1919 1919  ................
#0x00b0:  1919 1919 1919 1919 1919 ffc0 0011 0802  ................
#0x00c0:  d005 0003 0121 0002 1101 0311 01ff c400  .....!..........
#0x00d0:  1f00 0001 0501 0101 0101 0100 0000 0000  ................
#0x00e0:  0000 0001 0203 0405 0607 0809 0a0b ffc4  ................
#0x00f0:  00b5 1000 0201 0303 0204 0305 0504 0400  ................


#  | 2B – frame number | 2B – frame chunk number | data |
# * frame number – (unsigned int, big endian) all chunks within  one JPEG have same frame number, increments by 0×01
# * frame chunk number – (unsigned int, big endian) first image chunk is 0×0000, increments by 0×01, last chunk has MSB set to 1
# 
# Thank you chinese engineers! Because of wrong length in IP header (1044) I have to listen on raw socket!

# I also wanted to be able to use only sender and PC. When I plugged in sender only, no stream was broadcasted 
# so I plugged in also the receiver a captured control frames.
# unicast to 48689/UDP with payload 0x5446367A600200000000000303010026000000000234C2

# The sender started to send stream for a few seconds and then stopped. 
# So I started to send control packets one per second and the stream was playing continuously. 


########

#Extra research
#-Packet at port 48689 (all values are hex, unless otherwise specified)
#–Receiver sends one when it receives one from the sender.\
#–Endianness is different in the packet counter than in the rest of the packets
#–[0..4] 5 byte header [54:46:36:7a:63]
#–[5] 1 byte define what you are
#—01 = Sender
#—02 = Receiver
#–[6...7] always 00 00
#–[8...9] 2 bytes of an internal counter of how many 48689 packages have been send. Overflows at ff ff back to 00 00 to 01 00
#–[10..18] two different sequences for sender / receiver
#—[00:03:03:03:00:24:00:00:00] = Sender
#—[00:03:03:01:00:26:00:00:00] = Receiver
#–[19...22] Uptime receiver in ms (0 for sender)
#All bytes are 0 for the receiver from now on to make a length of 512 bytes
#–[23...26] [00:00:00:00]
#–[27] Some flag byte to indicate the signal
#—03 for signal
#—10 for no signal
#–[28..29] Width of signal (probably input or encoded width)
#–[30..31] Height of signal (probably input or encoded height)
#–[32..33] FPS of signal
#–[34..35] Width of signal (probably input or encoded width)
#–[36..37] Height of signal (probably input or encoded height)
#–[38..39] [00:78]
#–[40..43] Uptime in ms for the sender
#–[44..49] [00:01:00:00:00:00]
#–[50] Some indicater of number of receivers connected but doesn’t change when one disconnects
#—00 when none is connected
#—02 when one is connected
#–[51] [0a]
#For the rest it’s filled with 00′s to pad up to 520 bytes.
#-Packet on port 2067
#–This is a frame count packet.

# See latest update 
# http://codepad.org/L0v4hIJe
# http://codepad.org/VThPnCR5

