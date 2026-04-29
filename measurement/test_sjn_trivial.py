from traffic_common import *

resetInterface()

templates1 = [
    makeASTFTemplate(50009, 1_000_000, 10)
]
templates2 = [
    makeASTFTemplate(50008, 500_000, 30),
    makeASTFTemplate(50009, 1_000_000, 10)
]

runMeasurement("bfifo", None, templates2)
runMeasurement("rifo", "sjn", templates2)

#runMeasurement("rifo", "sjn", templates1)
runMeasurement("pifo", "sjn", templates2)
runMeasurement("sp_pifo", "sjn", templates2)
