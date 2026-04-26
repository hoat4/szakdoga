from traffic_common import *

# 40*100KB-ot viszünk át, azaz 320Kbit/s
# dropnak 0 közelinek kéne lennie, throughputnak mindegyik esetben kb. ugyanannyinak.
# SRTF most eléggé elrontja flow completion time-ot, főleg PIFO-nál.

resetInterface()

#profile = makeProfile(50011, 10000000, 10)
profile = makeProfile(50009, 1_000_000, 40)

runMeasurement("bfifo", None, profile)
#runMeasurement("rifo", None) ezeket is lehet nézni, de ugyanaz lenne mint SJN-nek, mert csak egyetlen flow hossz van
#runMeasurement("pifo", None)
#runMeasurement("sp_pifo", None)
runMeasurement("rifo", "sjn", profile)
runMeasurement("pifo", "sjn", profile)
runMeasurement("sp_pifo", "sjn", profile)
runMeasurement("rifo", "srtf", profile)
runMeasurement("pifo", "srtf", profile)
runMeasurement("sp_pifo", "srtf", profile)
