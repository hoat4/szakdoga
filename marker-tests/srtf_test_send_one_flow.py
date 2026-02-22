from marker_test_common import *
import random
import time
import math

flow = Flow(50003)

while flow.remainingBytes > 0:
    expectedRank = math.floor(math.sqrt(flow.remainingBytes))
    flow.sendPacketWithExpectedRank(expectedRank)
    time.sleep(0.05)
