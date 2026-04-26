from trex.astf.api import *
from prometheus_client import start_http_server, Gauge, Histogram, Counter, Summary
import time
import subprocess
import re
from scapy.all import *
from scapy.sendrecv import AsyncSniffer

def floatRange(begin, end, divisions):
    return [begin + (end - begin) * x / divisions for x in range(1, divisions + 1)]

labelNames = ["scheduler", "marker"]
throughputGauge = Gauge('vacak_throughput', "áteresztőképesség L7-ben (bytes/s)", labelNames)
ipacketsGauge = Gauge('vacak_packets_in', "bejövő csomagok", labelNames)
opacketsGauge = Gauge('vacak_packets_out', "kimenő csomagok", labelNames)
flowCompletionTimeSummary = Summary('vacak_flow_completion_time', "flow completion time (s)", labelNames)
latencyGauge = Gauge('vacak_latency', "Queue-ban töltött átlagos idő (ms)", labelNames)
queueUsage = Gauge('vacak_queue_usage', "Queue kihasználtsága (0-1)", labelNames)
packetDropCounter = Gauge("vacak_packet_drop", "Droppolt packetek száma", labelNames + ["dropReason"])

start_http_server(18001)

def makeProfile(port, flowSize, cps):
    # client program
    prog_c = ASTFProgram()
    prog_c.connect()
    if flowSize <= 1_000_000:
        prog_c.send(b'x' * flowSize)
    else:
        if int(flowSize) != flowSize:
            raise Exception("larger than 1MB but not dividable by 1MB: " + str(flowSize))
        prog_c.set_var("var2", int(flowSize / 1_000_000));
        prog_c.set_label("a:");
        prog_c.send(b'x' * 1_000_000)
        prog_c.jmp_nz("var2","a:") 

    # Server program
    prog_s = ASTFProgram()
    prog_s.accept()

    # Receive from client
    prog_s.recv(flowSize)

    ip_gen = ASTFIPGen(
        dist_client=ASTFIPGenDist(ip_range=["2.2.2.2", "2.2.2.2"]),
        dist_server=ASTFIPGenDist(ip_range=["1.1.1.1", "1.1.1.1"])
    )

    template = ASTFTemplate(
        client_template=ASTFTCPClientTemplate(
            program = prog_c,
            port = port,
            cps = cps, 
            ip_gen = ip_gen
        ),
        server_template=ASTFTCPServerTemplate(
            program = prog_s,
            assoc = ASTFAssociationRule(port=port)
        )
    )

    return ASTFProfile(
        default_ip_gen = ip_gen,
        templates = [template]
    )

global currentScheduler
global currentMarker

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
            flowCompletionTimeSummary.labels(scheduler=currentScheduler, marker=currentMarker).observe(flowCompletionTime)
        case _:
            raise Exception("unknown TCP flags: " + packet.summary())

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
      
    raise Exception("no line found in dmesg starting with \"" + prefix + "\"")

BFIFO_QUEUE_SIZE=100000

def runMeasurement(scheduler, marker):
    global currentScheduler
    global currentMarker

    print("Begin with scheduler: " + scheduler)
    currentScheduler = {
        "bfifo": "FIFO",
        "rifo": "RIFO", "pifo": "PIFO", "sp_pifo": "SP-PIFO", 
        "rifo_debug": "RIFO (debug)", "pifo_debug": "PIFO (debug)", "sp_pifo_debug": "SP-PIFO (debug)", 
    }[scheduler]
    currentMarker = marker if marker else "none"

    addQdiscCmd = ["tc", "qdisc", "add", "dev", "veth1", "parent", "1:1", scheduler]
    if scheduler == "bfifo":
        addQdiscCmd.extend(["limit", str(BFIFO_QUEUE_SIZE)])
    subprocess.run(addQdiscCmd, check=True)
    #subprocess.run(["tc", "qdisc", "add", "dev", "veth1", "root", scheduler], check=True)

    if marker:
        subprocess.run(["tc", "filter", "add", "dev", "veth1", "egress", "bpf", "da", "obj", marker + ".o"], check=True)

    AsyncSniffer(filter = "tcp[tcpflags] & (tcp-syn|tcp-fin) > 0", iface = "veth2", prn=handleSniffedPacket).start()

    c = ASTFClient()
    c.connect()
    c.reset()
    c.load_profile(makeProfile(50011, 10000000, 10))

    c.clear_stats()
    c.start(mult = 1, duration = 10)

    while c.get_active_ports():
        stats = c.get_stats()
        ipacketsGauge.labels(scheduler=currentScheduler, marker=currentMarker).set(stats['total']['ipackets'])
        opacketsGauge.labels(scheduler=currentScheduler, marker=currentMarker).set(stats['total']['opackets'])
        throughputGauge.labels(scheduler=currentScheduler, marker=currentMarker).set(stats['traffic']['server']['m_rx_bw_l7_r']) # vagy client.m_tx_bw_l7_r?

        if scheduler != "bfifo":
            subprocess.run(["tc", "qdisc", "show", "dev", "veth1"], check=True)
            prefix = "[" + {"rifo": "RIFO", "pifo": "PIFO", "sp_pifo": "SP-PIFO", 
                            "rifo_debug": "RIFO", "pifo_debug": "PIFO", "sp_pifo_debug": "SP-PIFO"}[scheduler] + "] Statistics: "
            msg = findInDMesg(prefix)[len(prefix):]
            for stat in msg.split(", "):
                [statName, statVal] = stat.split(": ")
                if statName == "latency": 
                    statVal = statVal.split(" = ")[1]
                if statName == "queue usage":
                    [packetsInQueue, queueSize] = statVal.split(" / ")
                    statVal = float(packetsInQueue) / float(queueSize)
                else:
                    statVal = float(statVal)
                if statName == "latency":
                    statVal = statVal / 1000000 # ns -> ms
                counter = {
                    "latency": latencyGauge.labels(scheduler = currentScheduler, marker = currentMarker),
                    "queue usage": queueUsage.labels(scheduler = currentScheduler, marker = currentMarker),
                    "drop because full": packetDropCounter.labels(scheduler = currentScheduler, marker = currentMarker, dropReason = "queueFull"),
                    "drop because priority too low": packetDropCounter.labels(scheduler = currentScheduler, marker = currentMarker, dropReason = "priorityTooLow"), 
                    "drop old": packetDropCounter.labels(scheduler = currentScheduler, marker = currentMarker, dropReason = "dropOld"),
                    "drop new": packetDropCounter.labels(scheduler = currentScheduler, marker = currentMarker, dropReason = "dropNew"),
                    "drop new because drop old was not enough": 
                        packetDropCounter.labels(scheduler = currentScheduler, marker = currentMarker, dropReason = "dropNewBecauseDropOldNotEnough"),
                }[statName]
                counter.set(statVal)
        else:
            # natív qdisc

            output = subprocess.check_output(["tc", "-s", "qdisc", "show", "dev", "veth1", "parent", "1:1"], text=True)
            for line in output.splitlines():
                match = re.search(r'backlog (\d+)b (\d+)p', line) # pl.: backlog 1514b 1p requeues 0
                if match:
                    queueUsage.labels(scheduler = currentScheduler, marker = currentMarker).set(float(match.group(1)) / float(BFIFO_QUEUE_SIZE))
                match = re.search(r'dropped (\d+)', line) # pl.: Sent 410142438 bytes 273799 pkt (dropped 3243, overlimits 0 requeues 0)
                if match:
                    packetDropCounter.labels(scheduler = currentScheduler, marker = currentMarker, dropReason = "queueFull").set(int(match.group(1)))

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
    flowCompletionTimeSummary.clear()
    latencyGauge.clear()
    packetDropCounter.clear()

    subprocess.run(["tc", "qdisc", "del", "dev", "veth1", "parent", "1:1"], check=True)
    if marker:
        subprocess.run(["tc", "filter", "del", "dev", "veth1", "egress"], check=True)
    #subprocess.run(["tc", "qdisc", "del", "dev", "veth1", "root", scheduler], check=True)

print("Removing leftover qdiscs")
subprocess.run(["tc", "qdisc", "del", "dev", "veth1", "parent", "1:1", "bfifo"])
subprocess.run(["tc", "qdisc", "del", "dev", "veth1", "parent", "1:1", "pfifo_fast"])
subprocess.run(["tc", "qdisc", "del", "dev", "veth1", "parent", "1:1", "rifo"])
subprocess.run(["tc", "qdisc", "del", "dev", "veth1", "parent", "1:1", "pifo"])
subprocess.run(["tc", "qdisc", "del", "dev", "veth1", "parent", "1:1", "sp_pifo"])
subprocess.run(["tc", "qdisc", "del", "dev", "veth1", "parent", "1:1", "rifo_debug"])
subprocess.run(["tc", "qdisc", "del", "dev", "veth1", "parent", "1:1", "pifo_debug"])
subprocess.run(["tc", "qdisc", "del", "dev", "veth1", "parent", "1:1", "sp_pifo_debug"])
print("Done removing leftover qdiscs")
print("Removing leftover qdiscs")
subprocess.run(["tc", "filter", "del", "dev", "veth1", "egress"], check=True) # ez nem dob hibát akkor se, ha nincs filter
    
runMeasurement("bfifo", None)
runMeasurement("rifo", None)
runMeasurement("pifo", None)
runMeasurement("sp_pifo", None)
runMeasurement("rifo", "sjn")
runMeasurement("pifo", "sjn")
runMeasurement("sp_pifo", "sjn")
runMeasurement("rifo", "srtf")
runMeasurement("pifo", "srtf")
runMeasurement("sp_pifo", "srtf")
