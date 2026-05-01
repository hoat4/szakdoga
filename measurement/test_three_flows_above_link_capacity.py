from traffic_common import *

flows = [
    FLOW_10KB * 40, # 4MBps = 3,2Mbps
    FLOW_100KB * 20, # 20MBps = 16Mbps
    FLOW_1MB * 12, # 96Mbps
]

# tehát összesen 1152 Mbps, míg a bottleneck 1Gbps

runMeasurement("bfifo", None, flows)
#runMeasurement("rifo", None, profiles)
runMeasurement("rifo", "sjn", flows)
runMeasurement("pifo", "sjn", flows)
runMeasurement("sp_pifo", "sjn", flows)
