from scheduler_test_common import *
import time

initScheduler("sp_pifo", "10Kbit")

QUEUE_COUNT = 8

for i in range(QUEUE_COUNT, -1, -1):
    sendWithRank(i, 30)
    time.sleep(0.5)

sendWithRank(2, 30)

# először bekerül mindegyik rangú csomag az eggyel kisebb számú queueba, viszont a 0-ás rangú packet
# küldésekor megváltozik az összes queue boundja, és ezért a végén a 2-es rangú packetnek már nem 
# az 1-es, hanem a 2-es számú queue-ba kell belekerülnie.
# illetve látszódnia kell "Push down because rank 0 < 1: decrement 1 from all queues" üzenetnek
# a 0-ás packetnél.
