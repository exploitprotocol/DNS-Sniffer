#!usr/bin/python
""" DNSnif.py-It basically captures all the DNS Queries from the traffic and It can be used 
    with an arp poisioning tool to capture the all the DNS Queries over the network
    
    Author:Aditya Agrawal
    Twitter: @exploitprotocol
    Author is not responsible for any effect's caused by this script
"""

from scapy.all import *

serverip=raw_input("Input IP Address of DNS Server : ")
result={}
def packetHandler(pkt):
	if pkt.haslayer(DNSQR):	
		if pkt[DNSQR].qname[0:-1] in result.keys():
			result[pkt[DNSQR].qname[0:-1]]=result[pkt[DNSQR].qname[0:-1]]+1
		else:
			result[pkt[DNSQR].qname[0:-1]]=1
def printResult():
	final=sorted(result,key=lambda x: result[x])
	print "No Of Times Visited"+"   "+"Domain Visited"
	for x in final:
		print "     "+str(result[x])+"                 "+x	
def liveView(pkt):
	if pkt.haslayer(DNSQR):
		print pkt[DNSQR].qname[0:-1]
view=raw_input("Enter s if you want to store then show result's and l for liveview : ")
if view=='s':
	query=raw_input("Input No. Of queries to be sniffed : ")
	sniff(count=int(query),filter="udp port 53 and ip src "+str(serverip),prn=packetHandler)
elif view=='l':
	sniff(filter="udp port 53 and ip src "+str(serverip),prn=liveView)
printResult()
