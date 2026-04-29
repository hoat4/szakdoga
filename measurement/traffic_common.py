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
throughputGauge = Gauge('throughput_l1', "áteresztőképesség (bps)", labelNames)
throughputL7Gauge = Gauge('throughput_l7', "áteresztőképesség L7-ben (bps)", labelNames)
ipacketsGauge = Gauge('packets_in', "bejövő csomagok", labelNames)
opacketsGauge = Gauge('packets_out', "kimenő csomagok", labelNames)
flowCompletionTimeSummary = Summary('flow_completion_time', "flow completion time (s)", labelNames + ["flowSize"])
latencyGauge = Gauge('queueing_delay', "Queue-ban töltött átlagos idő (ms)", labelNames)
queueUsage = Gauge('queue_occupancy', "Queue kihasználtsága (0-1)", labelNames)
packetDropCounter = Gauge("packet_drop", "Droppolt packetek száma", labelNames + ["dropReason"])
flowBeginCounter = Counter("connection_opens", "Megnyitott TCP kapcsolatok száma", labelNames + ["flowSize"])
finishedFlowSizes = Counter("estimated_l7_throughput", "A flow bezárások alapcsán becsült áteresztőképesség", labelNames + ["flowSize"])

start_http_server(18001)

ip_gen = ASTFIPGen(
    dist_client=ASTFIPGenDist(ip_range=["2.2.2.1", "2.2.2.255"]),
    dist_server=ASTFIPGenDist(ip_range=["1.1.1.1", "1.1.1.1"])
)

def makeASTFTemplate(port, flowSize, cps):
    # client program
    prog_c = ASTFProgram()
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
    prog_s.recv(flowSize)

    return ASTFTemplate(
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

global currentScheduler
global currentMarker
global connectionBeginCount
global connectionBeginNotDetected

connectionBegins = {}
connectionBeginCount = 0
connectionBeginNotDetected = 0

def handleSniffedPacket(packet):
    global connectionBeginCount
    global connectionBeginNotDetected

    if not packet[IP].src.startswith("2."):
        return
    #print(packet.summary())
    now = time.monotonic()
    connectionID = str(packet[TCP].sport) + "-" + str(packet[TCP].dport)
    match packet[TCP].flags:
        case "S":
            #print(str(now) + " Conn begin " + str(packet[TCP].sport) + " -> " + str(packet[TCP].dport))
            connectionBegins[connectionID] = now
            flowBeginCounter.labels(scheduler=currentScheduler, marker=currentMarker, flowSize = destPortToFlowSizeStr(packet[TCP].dport)).inc()
            connectionBeginCount = connectionBeginCount + 1
        case "FA":
            if connectionID not in connectionBegins:
                connectionBeginNotDetected = connectionBeginNotDetected + 1
                print("Flow begin not detected: " + connectionID)
                return
            beginTime = connectionBegins[connectionID]
            flowCompletionTime = now-beginTime
            #print(str(time.monotonic()) + " Conn end " + str(packet[TCP].sport) + " -> " + str(packet[TCP].dport)+
            #      " with scheduler "+ currentScheduler+" in " + str(flowCompletionTime) + " seconds")
            flowCompletionTimeSummary.labels(scheduler=currentScheduler, marker=currentMarker, flowSize = destPortToFlowSizeStr(packet[TCP].dport)).observe(flowCompletionTime)
            finishedFlowSizes.labels(scheduler=currentScheduler, marker=currentMarker, flowSize = destPortToFlowSizeStr(packet[TCP].dport)).inc(destPortToFlowSize(packet[TCP].dport))
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

    lastLine = ""

    foundOne = False
    foundLastLine = False
    for line in reversed(process.stdout.splitlines()):
        if not foundLastLine:
            lastLine = line
            foundLastLine = True
        if line.startswith(prefix):
            if foundOne:
                return line
            else:
                foundOne = True
      
    raise Exception("no line found in dmesg starting with \"" + prefix + "\". Last line: " + lastLine)

BFIFO_QUEUE_SIZE=100000

txInterfaceName = "veth1"
txInterfaceQDiscClass = ["parent", "1:1"] # [ "root" ]
rxInterfaceName = "veth2"


def runMeasurement(scheduler, marker, astfTemplates):
    global currentScheduler
    global currentMarker
    global connectionBeginCount
    global connectionBeginNotDetected
    global connectionBegins

    print("Begin with scheduler: " + scheduler)
    currentScheduler = {
        "bfifo": "FIFO",
        "rifo": "RIFO", "pifo": "PIFO", "sp_pifo": "SP-PIFO", 
        "rifo_debug": "RIFO (debug)", "pifo_debug": "PIFO (debug)", "sp_pifo_debug": "SP-PIFO (debug)", 
    }[scheduler]
    currentMarker = marker if marker else "none"

    addQdiscCmd = ["tc", "qdisc", "add", "dev", txInterfaceName] + txInterfaceQDiscClass + [scheduler]
    if scheduler == "bfifo":
        addQdiscCmd.extend(["limit", str(BFIFO_QUEUE_SIZE)])
    subprocess.run(addQdiscCmd, check=True)

    print(str(addQdiscCmd))
    #subprocess.run(["tc", "qdisc", "add", "dev", whichInterfaceForScheduler, "root", scheduler], check=True)

    if marker:
        subprocess.run(["tc", "filter", "add", "dev", txInterfaceName, "egress", "bpf", "da", "obj", marker + ".o"], check=True)

    sniffer = AsyncSniffer(filter = "tcp[tcpflags] & (tcp-syn|tcp-fin) > 0", iface = rxInterfaceName, prn=handleSniffedPacket)
    sniffer.start()

    c = ASTFClient()
    c.connect()
    c.reset()
    c.load_profile(ASTFProfile(
        default_ip_gen = ip_gen,
        templates = astfTemplates
    ))

    c.clear_stats()

    begin = time.monotonic()

    c.start(mult = 1, duration = 10)

    while c.get_active_ports():
        stats = c.get_stats()
        ipacketsGauge.labels(scheduler=currentScheduler, marker=currentMarker).set(stats['total']['ipackets'])
        opacketsGauge.labels(scheduler=currentScheduler, marker=currentMarker).set(stats['total']['opackets'])
        throughputGauge.labels(scheduler=currentScheduler, marker=currentMarker).set(stats[0]['tx_bps_L1'])
        throughputL7Gauge.labels(scheduler=currentScheduler, marker=currentMarker).set(stats['traffic']['server']['m_rx_bw_l7_r']) # vagy client.m_tx_bw_l7_r?

        connectionCountMsg = "Snooped connection begin count: " + str(connectionBeginCount) + "; not detected: " + str(connectionBeginNotDetected)
        if "tcps_accepts" in stats["traffic"]["server"]:
            connectionCountMsg = connectionCountMsg + "; TRex server TCP accepts: " + str(stats["traffic"]["server"]["tcps_accepts"])
            connectionCountMsg = connectionCountMsg + "; TRex client TCP conn attempts: " + str(stats["traffic"]["client"]["tcps_connattempt"])
        print(connectionCountMsg)

        if scheduler != "bfifo":
            subprocess.run(["tc", "qdisc", "show", "dev", txInterfaceName], check=True, stdout=subprocess.PIPE)
            prefix = "[" + {"rifo": "RIFO", "pifo": "PIFO", "sp_pifo": "SP-PIFO", 
                            "rifo_debug": "RIFO", "pifo_debug": "PIFO", "sp_pifo_debug": "SP-PIFO"}[scheduler] + "] Statistics: "
            msg = findInDMesg(prefix)[len(prefix):]

            #print(msg)
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
                metric = None
                match statName:
                    case "latency":
                        metric = latencyGauge.labels(scheduler = currentScheduler, marker = currentMarker)
                    case "queue usage":
                        metric = queueUsage.labels(scheduler = currentScheduler, marker = currentMarker)
                    case "drop because full":
                        metric = packetDropCounter.labels(scheduler = currentScheduler, marker = currentMarker, dropReason = "queueFull")
                    case "drop because priority too low":
                        metric = packetDropCounter.labels(scheduler = currentScheduler, marker = currentMarker, dropReason = "priorityTooLow")
                    case "drop old":
                        metric = packetDropCounter.labels(scheduler = currentScheduler, marker = currentMarker, dropReason = "dropOld")
                    case "drop new":
                        metric = packetDropCounter.labels(scheduler = currentScheduler, marker = currentMarker, dropReason = "dropNew")
                    case "drop new because drop old was not enough":
                        metric = packetDropCounter.labels(scheduler = currentScheduler, marker = currentMarker, dropReason = "dropNewBecauseDropOldNotEnough")
                    case _:
                        raise Exception("unknown stat name: " + str(statName))
                metric.set(statVal)
        else:
            # natív qdisc

            output = subprocess.check_output(["tc", "-s", "qdisc", "show", "dev", txInterfaceName] + txInterfaceQDiscClass, text=True)
            for line in output.splitlines():
                match = re.search(r'backlog (\d+)b (\d+)p', line) # pl.: backlog 1514b 1p requeues 0
                if match:
                    queueUsage.labels(scheduler = currentScheduler, marker = currentMarker).set(float(match.group(1)) / float(BFIFO_QUEUE_SIZE))
                match = re.search(r'dropped (\d+)', line) # pl.: Sent 410142438 bytes 273799 pkt (dropped 3243, overlimits 0 requeues 0)
                if match:
                    packetDropCounter.labels(scheduler = currentScheduler, marker = currentMarker, dropReason = "queueFull (" + currentScheduler + ")").set(int(match.group(1)))

        time.sleep(0.1)

    # végén m_tx_bw_l7_total_r-et lehetne kiírni stdoutra

    stats = c.get_stats()
    ipackets  = stats['total']['ipackets']
    opackets  = stats['total']['opackets']

    print("Done with scheduler {0} in {1} seconds - Packets Sent: {2}, Received: {3}".
          format(scheduler, time.monotonic() - begin, opackets, ipackets))
    
    print(stats)

    ipacketsGauge.clear()
    opacketsGauge.clear()
    throughputGauge.clear()
    throughputL7Gauge.clear()
    flowCompletionTimeSummary.clear()
    latencyGauge.clear()
    packetDropCounter.clear()
    finishedFlowSizes.clear()
    connectionBeginCount = 0
    connectionBeginNotDetected = 0
    connectionBegins = {}
    sniffer.stop()
    sniffer.join()

    subprocess.run(["tc", "qdisc", "del", "dev", txInterfaceName] + txInterfaceQDiscClass, check=True)
    if marker:
        subprocess.run(["tc", "filter", "del", "dev", txInterfaceName, "egress"], check=True)
    #subprocess.run(["tc", "qdisc", "del", "dev", whichInterfaceForScheduler, "root", scheduler], check=True)

    time.sleep(1.5) # finishedFlowSizes grafikon részei kevésbé csússzanak össze

def resetInterface():
    print("Removing leftover qdiscs")
    subprocess.run(["tc", "qdisc", "del", "dev", txInterfaceName] + txInterfaceQDiscClass + ["bfifo"])
    subprocess.run(["tc", "qdisc", "del", "dev", txInterfaceName] + txInterfaceQDiscClass + ["pfifo_fast"])
    subprocess.run(["tc", "qdisc", "del", "dev", txInterfaceName] + txInterfaceQDiscClass + ["rifo"])
    subprocess.run(["tc", "qdisc", "del", "dev", txInterfaceName] + txInterfaceQDiscClass + ["pifo"])
    subprocess.run(["tc", "qdisc", "del", "dev", txInterfaceName] + txInterfaceQDiscClass + ["sp_pifo"])
    subprocess.run(["tc", "qdisc", "del", "dev", txInterfaceName] + txInterfaceQDiscClass + ["rifo_debug"])
    subprocess.run(["tc", "qdisc", "del", "dev", txInterfaceName] + txInterfaceQDiscClass + ["pifo_debug"])
    subprocess.run(["tc", "qdisc", "del", "dev", txInterfaceName] + txInterfaceQDiscClass + ["sp_pifo_debug"])
    print("Done removing leftover qdiscs")
    print("Removing leftover filters")
    subprocess.run(["tc", "filter", "del", "dev", txInterfaceName, "egress"], check=True) # ez nem dob hibát akkor se, ha nincs filter

def destPortToFlowSize(destPort):
    return {
        50001: 100, 
        50002: 500,
        50003: 1000,
        50004: 5000,
        50005: 10_000,
        50006: 50_000,
        50007: 100_000,
        50008: 500_000,
        50009: 1_000_000,
        50010: 5_000_000,
        50011: 10_000_000,
        50012: 50_000_000,
        50013: 100_000_000,
        50014: 500_000_000,
        50015: 1_000_000_000
    }[destPort]

def destPortToFlowSizeStr(destPort):
    return {
        50001: "100 B", 
        50002: "500 B",
        50003: "1 KB",
        50004: "5 KB",
        50005: "10 KB",
        50006: "50 KB",
        50007: "100 KB",
        50008: "500 KB",
        50009: "1 MB",
        50010: "5 MB",
        50011: "10 MB",
        50012: "50 MB",
        50013: "100 MB",
        50014: "500 MB",
        50015: "1 GB"
    }[destPort]
