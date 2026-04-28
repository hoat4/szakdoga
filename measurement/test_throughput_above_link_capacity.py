from traffic_common import *

resetInterface()

profiles = [
    makeASTFTemplate(50005, 10_000, 40), # 40 * 10KB = 4MBps = 3,2Mbps
    makeASTFTemplate(50007, 100_000, 20), # 20 * 100KB = 20MBps = 16Mbps
    makeASTFTemplate(50009, 1_000_000, 12), # 12MBps = 96Mbps
]

# tehát összesen 1152 Mbps, míg a bottleneck 1Gbps

runMeasurement("bfifo", None, profiles)
#runMeasurement("rifo", None, profiles)
runMeasurement("rifo", "sjn", profiles)
runMeasurement("pifo", "sjn", profiles)
runMeasurement("sp_pifo", "sjn", profiles)
