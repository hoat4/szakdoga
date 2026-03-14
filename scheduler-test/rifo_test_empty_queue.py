from scheduler_test_common import *
import time

initScheduler("rifo", "10Kbit")

for i in range(0, 10):
    sendWithRank(1, 30)
    time.sleep(1)
