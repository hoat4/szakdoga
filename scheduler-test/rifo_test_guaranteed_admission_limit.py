from scheduler_test_common import *

initScheduler("rifo", "10Kbit")

for i in range(0, 20):
    rank = 10000 if i % 2 == 0 else 1
    sendWithRank(rank, 90)

print("Done")

# a queue használtsága 660-ig ment fel. mivel 10000 a length, 
# ezért 1000 a guaranteed_admission_limit, ezért az mindegyik packetet át kell engednie.
# tehát a teszt sikeres, ha nincs benne dropped (kivéve ha túlmegy a 1000-en a kihasználtság, akkor azokat nem kell figyelembe venni)

