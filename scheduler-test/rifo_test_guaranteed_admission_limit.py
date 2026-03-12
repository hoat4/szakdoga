from scapy.all import *

# update interval = 5, ezért elég 10 packet (6 is elég lenne)

for i in range(0, 20):
    rank = 10000 if i % 2 == 0 else 1

    print("Send with rank " + str(rank))
    p = IP(dst="10.0.0.1", id = rank) / UDP(sport = 12345, dport=50005) / ("abc" * 30) 
    send(p)

print("Done")

# a queue használtsága 660-ig ment fel. mivel 10000 a length, 
# ezért 1000 a guaranteed_admission_limit, ezért az mindegyik packetet át kell engednie.
# tehát a teszt sikeres, ha nincs benne dropped (kivéve ha túlmegy a 1000-en a kihasználtság, akkor azokat nem kell figyelembe venni)

