from scapy.all import *
from marker_test_common import *
import random
import time
import math

for k in range(10):
    flow = Flow(random.choice([50003, 50004, 50005, 50006]))
    while flow.remainingBytes > 0:
        expectedRank = math.floor(math.sqrt(flow.remainingBytes))
        flow.sendPacketWithExpectedRank(expectedRank)
        time.sleep(0.05)

# TODO kell tesztelni ha több packetet küldünk mint a flow hossza?