from scheduler_test_common import *
import time

initScheduler("pifo", "10Kbit")

for i in range(0, 10):
    sendWithRank(1, 30)
    time.sleep(0.5)

# dmesg-ben azt kell látnunk, hogy mindegyik packetet acceptelte, 0 queue hossz mellett
