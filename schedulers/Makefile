TARGET := vacak
CFLAGS += -g -DDEBUG
CFLAGS += -DRIFO_QUEUE_LENGTH=10000 -DRIFO_UPDATE_INTERVAL=5 -DPIFO_QUEUE_LENGTH_BYTES=10000 
CC += ${CFLAGS}

# 2500000, 100

obj-m += rifo.o sp_pifo.o pifo.o
vacak:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	EXTRA_CFLAGS="${CFLAGS}"

rifo_load:
	-rmmod rifo
	insmod rifo.ko

rifo_load_into_mininet:
	-tc qdisc del dev s1-eth1 root rifo
	-rmmod rifo
	insmod rifo.ko
	tc qdisc add dev s1-eth1 root rifo

pifo_load:
	-rmmod pifo
	insmod pifo.ko

pifo_load_into_mininet:
	-tc qdisc del dev s1-eth1 root pifo
	-rmmod pifo
	insmod pifo.ko
	tc qdisc add dev s1-eth1 root pifo

sp_pifo_load:
	-rmmod sp_pifo
	insmod sp_pifo.ko

sp_pifo_load_into_mininet:
	-tc qdisc del dev s1-eth1 root pifo
	-rmmod pifo
	insmod pifo.ko
	tc qdisc add dev s1-eth1 root pifo

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
