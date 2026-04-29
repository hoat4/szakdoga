from scheduler_test_common import *
import subprocess
import time

initScheduler("sp_pifo", "1Kbit")

# megtöltünk egy queuet, utolsó néhányat droppolnia kell
for i in range(0, 16):
    sendWithRank(5, 1000)

# újabb queuet kezdünk el megtölteni, ezt egy darabig engednie kell
for i in range(0, 16):
    sendWithRank(4, 1000)

print("Done")

# dmesg-ben azt kell látnunk, hogy az 5-ös rankú packetek közül eldobja az utolsó ötöt, 
# míg a 4-es rankúakból enqueue-olja az első kb. tízet, és csak az utána jövőeket droppolja
