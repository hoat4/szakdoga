from trex.astf.api import *
from prometheus_client import start_http_server, Gauge
import time

ipacketsGauge = Gauge('vacak_packets_in', "bejövő csomagok")
opacketsGauge = Gauge('vacak_packets_out', "kimenő csomagok")

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
            cps = 1, 
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

c = ASTFClient()
c.connect()
c.reset()
c.load_profile(makeProfile())

c.clear_stats()
c.start(mult = 1, duration = 100)
while c.get_active_ports():
    stats = c.get_stats()
    ipacketsGauge.set(stats['total']['ipackets'])
    opacketsGauge.set(stats['total']['opackets'])
    time.sleep(1)

stats = c.get_stats()
ipackets  = stats['total']['ipackets']
opackets  = stats['total']['opackets']

print("Done - Packets Sent: {0}, Received: {1}".format(opackets, ipackets))
print(stats)
