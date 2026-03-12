from rifo_test_common import *

# TODO az elején kéne resetelni a schedulert, mert különben lehet, 
#      hogy pont akkor resetlődik a counter, amikor a 2-es rangút küldenénk

# mivel az update interval a teszt során 5, ezért 18 packet bőven elég arra, hogy
# törlődjön az előző tesztekből hátramaradt megmaradt min/max
PACKETS = 20

# az első 4 packetnél nem működik még rendesen a htb rate limitje, és azok rögtön dequeuezva lesznek.
# de a 18. packetnél már kb. 7046/10000 lesz a queue telítettsége.

for i in range(0, PACKETS):
    rank = 2 if i == PACKETS - 2 else 1
    sendWithRank(rank, 500)

# Akkor sikeres a teszt, ha dmesg-ben azt látjuk, hogy az utolsó előttit eldobja,
# mert már eléggé tele van a queue, és alacsonyabb rankú, viszont
# az utolsót viszont megtartja, mert kis hely még van a queueban.

print("Done")

