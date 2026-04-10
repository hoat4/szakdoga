from prometheus_client import start_http_server, Gauge
import time
import random

gauge = Gauge('tesztvacak', 'szöveg')

start_http_server(18001)

while True:
    gauge.set(random.randint(0, 100))
    time.sleep(2)
