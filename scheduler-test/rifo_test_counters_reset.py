from rifo_test_common import *

# update intervalról feltesszük hogy 5

# hogy ne lehessen hogy folyton az első ciklusban küldött packetek után 
# resetelődik a counter, ezért lett 20 helyett 22 packet.

for i in range(0, 11):
    sendWithRank(1, 10)
    sendWithRank(10, 10)

for i in range(0, 10):
    sendWithRank(5, 10)

print("Done")

# a teszt sikeres, ha dmesgben azt látjuk, az 5 rangú csomagok között maximum az ötödiknél lesz a min/max 5/5-re átírva
