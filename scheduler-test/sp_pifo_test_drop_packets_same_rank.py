from scheduler_test_common import *
import subprocess
import time

initScheduler("sp_pifo", "10Kbit", showIncomingPackets=True)

for i in range(0, 16):
    sendWithRank(0, 1000)

print("Done")

# dmesg-ben azt kell látnunk, hogy kb. 5-6 darab droppolt packet van
