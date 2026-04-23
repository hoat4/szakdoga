from scapy.all import *

from mininet.net import Mininet
from mininet.nodelib import LinuxBridge
import mininet.log
import sys
import time
import subprocess


def executeInMininet(schedulerName, bandwidth, showIncomingPackets):
    # enélkül nem megy a waitOutput
    mininet.log.setLogLevel('info') 

    net = Mininet(ipBase='10.0.0.0/24')

    h1 = net.addHost('h1', ip = "10.0.0.1")
    h2 = net.addHost('h2', ip = "10.0.0.2")
    s1 = net.addSwitch('s1', cls=LinuxBridge)
    net.addLink(s1, h1)
    net.addLink(s1, h2)

    net.start()

    subprocess.run("tc qdisc add dev s1-eth1 root handle 1: htb default 1".split(), check=True)
    subprocess.run(["tc", "class", "add", "dev", "s1-eth1", "parent", "1:", "classid", "1:1", "htb", "rate", bandwidth, "ceil", bandwidth], check=True)
    subprocess.run(["tc", "qdisc", "add", "dev", "s1-eth1", "parent", "1:1", schedulerName], check=True)

    print("")

    if showIncomingPackets:
        h1.sendCmd("python \"" + sys.argv[0]+"\" h1")
    
    h2.sendCmd("python \"" + sys.argv[0]+"\" h2")    
    h2.waitOutput(verbose=True)

    print("")
    print("Inner process done")

    if showIncomingPackets:
        h1.sendInt()
        while h1.waiting:
            if not h1.waitReadable(100):
                break

            #subprocess.run(["tc", "qdisc", "show", "dev", "s1-eth1"], check=True)

            print(h1.monitor())

    net.stop()


def sendWithRank(rank, len):
    print("Send with rank " + str(rank) + " (" + str(len) + " bytes)")
    p = IP(dst="10.0.0.1", id = rank) / UDP(sport = 12345, dport=50005) / ("a" * len) 
    send(p)

def sendWithRankAndContent(rank, contentString):
    print("Send with rank " + str(rank) + ": " + contentString)
    p = IP(dst="10.0.0.1", id = rank) / UDP(sport = 12345, dport=50005) / contentString
    send(p)

def packetReceived(x):
    print("Received packet with rank " + str(x[IP].id) + " and contents: " + str(bytes(x[UDP].payload)))
    sys.stdout.flush()

def initScheduler(schedulerName, bandwidth, showIncomingPackets = False):
    if len(sys.argv) == 2 and sys.argv[1] == "h1":
        sniff(iface = 'h1-eth0', filter = "udp dst portrange 50001-50015", prn=packetReceived)
        exit()
            
    if len(sys.argv) == 1 or sys.argv[1] != "h2":
        executeInMininet(schedulerName + "_debug", bandwidth, showIncomingPackets)
        exit()
