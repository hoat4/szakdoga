from scheduler_test_common import *
import time

initScheduler("pifo", "10Kbit")

for i in range(0, 10):
    sendWithRank(1, 500)
    sendWithRank(2, 500)
