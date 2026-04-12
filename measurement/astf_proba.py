from trex.astf.api import *
from prometheus_client import start_http_server, Gauge, Histogram
import time
from scapy.all import *
from scapy.sendrecv import AsyncSniffer

throughputGauge = Gauge('vacak_throughput', "áteresztőképesség L7-ben")
ipacketsGauge = Gauge('vacak_packets_in', "bejövő csomagok")
opacketsGauge = Gauge('vacak_packets_out', "kimenő csomagok")
flowCompletionTimeHistogram = Histogram('vacak_flow_completion_time', "flow completion time")

start_http_server(18001)

def makeProfile():
    FLOW_SIZE = 5 * 1024 * 1024

    # client program
    prog_c = ASTFProgram()
    prog_c.connect()
    prog_c.send(b'x' * FLOW_SIZE)

    # Server program
    prog_s = ASTFProgram()
    prog_s.accept()

    # Receive from client
    prog_s.recv(FLOW_SIZE)

    ip_gen = ASTFIPGen(
        dist_client=ASTFIPGenDist(ip_range=["2.2.2.2", "2.2.2.2"]),
        dist_server=ASTFIPGenDist(ip_range=["1.1.1.1", "1.1.1.1"])
    )

    template = ASTFTemplate(
        client_template=ASTFTCPClientTemplate(
            program = prog_c,
            port = 50010,
            cps = 5, 
            ip_gen = ip_gen
        ),
        server_template=ASTFTCPServerTemplate(
            program = prog_s,
            assoc = ASTFAssociationRule(port=50010)
        )
    )

    return ASTFProfile(
        default_ip_gen = ip_gen,
        templates = [template]
    )

connectionBegins = {}
def handleSniffedPacket(packet):
    if packet[IP].src != "2.2.2.2":
        return
    #print(packet.summary())
    now = time.monotonic()
    connectionID = str(packet[TCP].sport) + "-" + str(packet[TCP].dport)
    match packet[TCP].flags:
        case "S":
            print(str(now) + " Conn begin " + str(packet[TCP].sport) + " -> " + str(packet[TCP].dport))
            connectionBegins[connectionID] = now
        case "FA":
            print(str(time.monotonic()) + " Conn end " + str(packet[TCP].sport) + " -> " + str(packet[TCP].dport))
            if connectionID not in connectionBegins:
                print("Flow begin not detected: " + connectionID)
                return
            beginTime = connectionBegins[connectionID]
            flowCompletionTimeHistogram.observe((now-beginTime) * 1000)
        case _:
            raise "unknown TCP flags: " + packet.summary()

AsyncSniffer(filter = "tcp[tcpflags] & (tcp-syn|tcp-fin) > 0", iface = "veth1", prn=handleSniffedPacket).start()

c = ASTFClient()
c.connect()
c.reset()
c.load_profile(makeProfile())

c.clear_stats()
c.start(mult = 1, duration = 50)

prevTime = time.monotonic()
prevConnCloses = 0
while c.get_active_ports():
    stats = c.get_stats()
    ipacketsGauge.set(stats['total']['ipackets'])
    opacketsGauge.set(stats['total']['opackets'])
    throughputGauge.set(stats['traffic']['server']['m_rx_bw_l7_r']) # vagy client.m_tx_bw_l7_r?
    #currConnCloses = stats['traffic']['server']['tcps_closed']
    #if currConnCloses > prevConnCloses:
        
    time.sleep(0.01)

# végén m_tx_bw_l7_total_r-et lehetne kiírni stdoutra

stats = c.get_stats()
ipackets  = stats['total']['ipackets']
opackets  = stats['total']['opackets']

print("Done - Packets Sent: {0}, Received: {1}".format(opackets, ipackets))
print(stats)
