from scheduler_test_common import *
import time

initScheduler("sp_pifo", "10Kbit")

for i in range(0, 10):
    sendWithRank(1, 30)
    time.sleep(0.5)

# dmesg-ben azt kell látnunk, hogy mindegyik packetet acceptelte a 7-es queueba, 
# 0 queue hossz mellett.
# kivéve a nem IP csomagokat, mert azoknak a rankját nem tudta megállapítani, ezért azok a 6-osba kerülnek.
