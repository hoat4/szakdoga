from traffic_common import *

resetInterface()

profiles = [
    makeASTFTemplate(50005, 10_000, 40), # 40 * 10KBps = 400KBps = 3,2Mbps
    makeASTFTemplate(50007, 100_000, 8), # 8 * 100KBps = 6,4Mbps
    makeASTFTemplate(50010, 5_000_000, 2), # 2 * 5MBps = 80Mbps
]

runMeasurement("bfifo", None, profiles)
#runMeasurement("rifo", None, profiles)
runMeasurement("pifo", "sjn", profiles)
runMeasurement("pifo", "srtf", profiles)
runMeasurement("sp_pifo", "sjn", profiles)
runMeasurement("rifo", "sjn", profiles)
