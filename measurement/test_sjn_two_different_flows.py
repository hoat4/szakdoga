from traffic_common import *

flows = [
    FLOW_500KB * 30,
    FLOW_1MB * 10
]

runMeasurement("bfifo", None, flows)
runMeasurement("rifo", "sjn", flows)
runMeasurement("pifo", "sjn", flows)
runMeasurement("sp_pifo", "sjn", flows)
