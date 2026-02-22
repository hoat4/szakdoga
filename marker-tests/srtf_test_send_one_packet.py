from marker_test_common import *
import math

flow = Flow(50003)

expectedRank = math.floor(math.sqrt(flow.remainingBytes))
flow.sendPacketWithExpectedRank(expectedRank)
