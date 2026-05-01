from traffic_common import *

flows = [
    FLOW_10KB * 40, # 400KBps = 3,2Mbps
    FLOW_100KB * 8, # 6,4Mbps
    FLOW_5MB * 2,   # 80Mbps
]

#setDuration(20)

runMeasurement("bfifo", None, flows)
#runMeasurement("rifo", None, flows)
runMeasurement("pifo", "sjn", flows)
runMeasurement("pifo", "srtf", flows)
runMeasurement("sp_pifo", "sjn", flows)
runMeasurement("rifo", "sjn", flows)
