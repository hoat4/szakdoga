from marker_test_common import *
import random
import time
import math

flows = []

for k in range(10):
    flows.append(Flow(random.choice([50003, 50004, 50005, 50006])))

while flows:
    flow = random.choice(flows)

    expectedRank = math.floor(math.sqrt(flow.remainingBytes))
    flow.sendPacketWithExpectedRank(expectedRank)
    
    if flow.remainingBytes <= 0:
        flows.remove(flow)
    time.sleep(0.05)
