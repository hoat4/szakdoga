from scheduler_test_common import *
import time

initScheduler("pifo", "10Kbit")

for i in range(0, 10):
    sendWithRank(1, 400)
    sendWithRank(2, 400)

time.sleep(5)

# dmesg-ben azt kell látni, hogy először az 1-es rankúakat dequeue-olja, majd a 2-eseket

