from scheduler_test_common import *
import time

initScheduler("sp_pifo", "10Kbit")

QUEUE_COUNT = 8

for i in range(QUEUE_COUNT - 1, -1, -1):
    sendWithRank(i, 30)
    time.sleep(0.5)

# dmesg-ben azt kell látnunk, hogy mindegyik packetet különböző queue-kba rakta, 0 queue hossz mellett.
# lesznek 0-ás ranknak számított packetek is, amik csak azért számítódtak annak, mert nem IP packetek, 
# ezért nem tudtunk a rankokat megállapítani, de nem kéne elvileg a sorrendbe bekavarnia.
