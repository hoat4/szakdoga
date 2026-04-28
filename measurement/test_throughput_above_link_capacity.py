from traffic_common import *

resetInterface()

profiles = [
    makeASTFTemplate(50005, 10_000, 400), # 400 * 10KB = 4MBps = 32Mbps
    makeASTFTemplate(50007, 100_000, 200), # 200 * 100KB = 20MBps = 160Mbps
    makeASTFTemplate(50009, 1_000_000, 120), # 120MBps = 960Mbps
]

# tehát összesen 1152 Mbps, míg a bottleneck 1Gbps

runMeasurement("bfifo", None, profiles)
#runMeasurement("rifo", None, profiles)
runMeasurement("rifo", "sjn", profiles)
runMeasurement("pifo", "sjn", profiles)
runMeasurement("sp_pifo", "sjn", profiles)
