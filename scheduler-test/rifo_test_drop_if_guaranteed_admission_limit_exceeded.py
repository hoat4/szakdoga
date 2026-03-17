from scheduler_test_common import *

initScheduler("rifo", "10Kbit")

for i in range(0, 30):
    rank = 10000 if i % 2 == 0 else 1
    len = 90
    sendWithRank(rank, len)

print("Done")

# a queue használtsága 1452/10000-ig ment fel.
# mivel 1000 a guaranteed_admission_limit, azt kell látnunk, hogy amint
# mint mint 1000 byte van a queueban, elkezdi eldobálni a nagyobb rangú packeteket, 
# de a kisebb rangúakat átengedi nagy queue hossz ellenére is.
