from traffic_common import *

# 40*100KB-ot viszünk át, azaz 32Mbps, ami kisebb mint a link sebessége (100Mbps).
# dropnak 0 közelinek kéne lennie, throughputnak mindegyik esetben kb. ugyanannyinak.
# SRTF most eléggé elrontja flow completion time-ot, főleg PIFO-nál.

resetInterface()

#profile = makeProfile(50011, 10000000, 10)
templates = [makeASTFTemplate(50009, 100_000, 4)]

runMeasurement("bfifo", None, templates)
#runMeasurement("rifo", None) ezeket is lehet nézni, de ugyanaz lenne mint SJN-nek, mert csak egyetlen flow hossz van
#runMeasurement("pifo", None)
#runMeasurement("sp_pifo", None)
runMeasurement("rifo", "sjn", templates)
runMeasurement("pifo", "sjn", templates)
runMeasurement("sp_pifo", "sjn", templates)
runMeasurement("rifo", "srtf", templates)
runMeasurement("pifo", "srtf", templates)
runMeasurement("sp_pifo", "srtf", templates)
