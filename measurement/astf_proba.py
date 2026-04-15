from trex.astf.api import *
from prometheus_client import start_http_server, Gauge, Histogram, Counter
import time
import subprocess
from scapy.all import *
from scapy.sendrecv import AsyncSniffer

def floatRange(begin, end, divisions):
    return [begin + (end - begin) * x / divisions for x in range(1, divisions + 1)]

throughputGauge = Gauge('vacak_throughput', "áteresztőképesség L7-ben (bytes/s)", ["scheduler"])
ipacketsGauge = Gauge('vacak_packets_in', "bejövő csomagok", ["scheduler"])
opacketsGauge = Gauge('vacak_packets_out', "kimenő csomagok", ["scheduler"])
flowCompletionTimeHistogram = Histogram('vacak_flow_completion_time', "flow completion time", ["scheduler"], 
                                        buckets = floatRange(0.25, 1, 20))
latencyGauge = Gauge('vacak_latency', "Queue-ban töltött átlagos idő (ms)", ["scheduler"])
packetDropCounter = Gauge("vacak_packet_drop", "Droppolt packetek száma", ["scheduler", "dropReason"])

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
            cps = 25, 
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

global currentScheduler

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
            if connectionID not in connectionBegins:
                print("Flow begin not detected: " + connectionID)
                return
            beginTime = connectionBegins[connectionID]
            flowCompletionTime = now-beginTime
            print(str(time.monotonic()) + " Conn end " + str(packet[TCP].sport) + " -> " + str(packet[TCP].dport)+
                  " with scheduler "+ currentScheduler+" in " + str(flowCompletionTime) + " seconds")
            flowCompletionTimeHistogram.labels(scheduler=currentScheduler).observe(flowCompletionTime)
        case _:
            raise "unknown TCP flags: " + packet.summary()

def findInDMesg(prefix):
    process = subprocess.run(
        ["dmesg", "-t"], # -t = without timestamps
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True
    )
    
    # tc qdisc showkor kétszer hívódik meg a qdisc dump, ezért
    # az utolsónál a latency ki lesz nullázódva

    foundOne = False
    for line in reversed(process.stdout.splitlines()):
        if line.startswith(prefix):
            if foundOne:
                return line
            else:
                foundOne = True
      
    raise "no line found in dmesg starting with \"" + prefix + "\""

NO_SCHEDULER = "none"
def runMeasurement(scheduler):
    global currentScheduler
    print("Begin with scheduler: " + scheduler)
    currentScheduler = scheduler

    if scheduler != NO_SCHEDULER:
        subprocess.run(["tc", "qdisc", "add", "dev", "veth2", "root", scheduler], check=True)

    AsyncSniffer(filter = "tcp[tcpflags] & (tcp-syn|tcp-fin) > 0", iface = "veth1", prn=handleSniffedPacket).start()

    c = ASTFClient()
    c.connect()
    c.reset()
    c.load_profile(makeProfile())

    c.clear_stats()
    c.start(mult = 1, duration = 15)

    while c.get_active_ports():
        stats = c.get_stats()
        ipacketsGauge.labels(scheduler=currentScheduler).set(stats['total']['ipackets'])
        opacketsGauge.labels(scheduler=currentScheduler).set(stats['total']['opackets'])
        throughputGauge.labels(scheduler=currentScheduler).set(stats['traffic']['server']['m_rx_bw_l7_r']) # vagy client.m_tx_bw_l7_r?

        if scheduler != NO_SCHEDULER:
            subprocess.run(["tc", "qdisc", "show", "dev", "veth2"], check=True)
            prefix = "[" + {"rifo": "RIFO", "pifo": "PIFO", "sp_pifo": "SP-PIFO"}[scheduler] + "] Statistics: "
            msg = findInDMesg(prefix)[len(prefix):]
            for stat in msg.split(", "):
                [statName, statVal] = stat.split(": ")
                if statName == "latency":
                    statVal = statVal.split(" = ")[1]
                statVal = float(statVal)
                if statName == "latency":
                    statVal = statVal / 1000000 # ns -> ms
                counter = {
                    "latency": latencyGauge.labels(scheduler = currentScheduler),
                    "drop because full": packetDropCounter.labels(scheduler = currentScheduler, dropReason = "queueFull"),
                    "drop because priority too low": packetDropCounter.labels(scheduler = currentScheduler, dropReason = "priorityTooLow"), 
                    "drop old": packetDropCounter.labels(scheduler = currentScheduler, dropReason = "dropOld"),
                    "drop new": packetDropCounter.labels(scheduler = currentScheduler, dropReason = "dropNew")
                }[statName]
                counter.set(statVal)

        time.sleep(0.01)

    # végén m_tx_bw_l7_total_r-et lehetne kiírni stdoutra

    stats = c.get_stats()
    ipackets  = stats['total']['ipackets']
    opackets  = stats['total']['opackets']

    print("Done with scheduler {0} - Packets Sent: {1}, Received: {2}".format(scheduler, opackets, ipackets))
    #print(stats)

    ipacketsGauge.clear()
    opacketsGauge.clear()
    throughputGauge.clear()
    flowCompletionTimeHistogram.clear()
    latencyGauge.clear()
    packetDropCounter.clear()

    if scheduler != NO_SCHEDULER:
        subprocess.run(["tc", "qdisc", "del", "dev", "veth2", "root", scheduler], check=True)

print("Removing leftover qdiscs")
subprocess.run(["tc", "qdisc", "del", "dev", "veth2", "root", "rifo"])
subprocess.run(["tc", "qdisc", "del", "dev", "veth2", "root", "pifo"])
subprocess.run(["tc", "qdisc", "del", "dev", "veth2", "root", "sp_pifo"])
print("Done removing leftover qdiscs")
    
runMeasurement(NO_SCHEDULER)
runMeasurement("rifo")
runMeasurement("pifo")
runMeasurement("sp_pifo")
