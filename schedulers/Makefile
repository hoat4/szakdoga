TARGET := vacak
CFLAGS += -g -DDEBUG -DRIFO_QUEUE_LENGTH=10000 -DRIFO_UPDATE_INTERVAL=5
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

sp_pifo_teszt:
	-tc class del dev s1-eth1 parent 1: classid 1:1
	-tc qdisc del dev s1-eth1 root
	-rmmod sp_pifo
	insmod sp_pifo.ko
	tc qdisc add dev s1-eth1 root handle 1: htb default 1
	tc class add dev s1-eth1 parent 1: classid 1:1 htb rate 10Mbit ceil 10Mbit
	tc qdisc add dev s1-eth1 parent 1:1 sp_pifo


pifo_teszt:
	-tc class del dev s1-eth1 parent 1: classid 1:1
	-tc qdisc del dev s1-eth1 root
	-rmmod pifo
	insmod pifo.ko
	tc qdisc add dev s1-eth1 root handle 1: htb default 1
	tc class add dev s1-eth1 parent 1: classid 1:1 htb rate 10Mbit ceil 10Mbit
	tc qdisc add dev s1-eth1 parent 1:1 pifo

