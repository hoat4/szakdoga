from scheduler_test_common import *
import time

initScheduler("pifo", "10Kbit", showIncomingPackets=True)

for i in range(0, 10):
    sendWithRankAndContent(1, "i=" + str(i) + " " * 200)
    sendWithRankAndContent(2, "i=" + str(i) + " " * 200)
    sendWithRankAndContent(3, "i=" + str(i) + " " * 200)
  
time.sleep(5)

# kimeneten bejövő packetek közt azt kell látnunk, hogy az azonos rankokhoz
# tartozó bejövő packetek megfelelő sorszámsorrendben vannak
