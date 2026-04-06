from scheduler_test_common import *
import time

initScheduler("pifo", "10Kbit")

# elvileg elég lenne 20*500 byte a 10000-es queuehossz megtöltéséhez, 
# de az első pár packetnél htb azonnal dequeueol
for i in range(0, 25):
    sendWithRank(5, 500)

sendWithRank(7, 500)
sendWithRank(3, 500)

time.sleep(1)

# dmesg-ben azt kell látni, hogy a végén a 7-es és 3-as rankú packetet is droppolja
# (meg előtte néhány 5-öset)
