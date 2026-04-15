TARGET := all
CFLAGS += -g
CFLAGS += -DRIFO_QUEUE_LENGTH=10000 -DRIFO_UPDATE_INTERVAL=5 -DPIFO_QUEUE_LENGTH_BYTES=10000 
CC += ${CFLAGS}

# 2500000, 100

ifeq ($(VARIANT),DEBUG)
	obj-m += rifo_debug.o sp_pifo_debug.o pifo_debug.o
	rifo_debug-objs := rifo.o
	pifo_debug-objs := pifo_main.o depq.o
	sp_pifo_debug-objs := sp_pifo.o
else
	obj-m += rifo.o sp_pifo.o pifo.o
	pifo-objs := pifo_main.o depq.o
endif

all: release debug

release:
	make -C /lib/modules/$(shell uname -r)/build VARIANT="RELEASE" M=$(PWD) EXTRA_CFLAGS="${CFLAGS}" modules
	mv rifo.ko rifo_release.ko
	mv pifo.ko pifo_release.ko
	mv sp_pifo.ko sp_pifo_release.ko

debug:
	make -C /lib/modules/$(shell uname -r)/build VARIANT=DEBUG M=$(PWD) EXTRA_CFLAGS="${CFLAGS} -DDEBUG" modules

load:
	-rmmod rifo
	-rmmod pifo
	-rmmod sp_pifo
	-rmmod rifo_debug
	-rmmod pifo_debug
	-rmmod sp_pifo_debug
	insmod rifo_release.ko
	insmod pifo_release.ko
	insmod sp_pifo_release.ko
	insmod rifo_debug.ko
	insmod pifo_debug.ko
	insmod sp_pifo_debug.ko

rifo_load_into_mininet:
	-tc qdisc del dev s1-eth1 root rifo
	-rmmod rifo
	insmod rifo.ko
	tc qdisc add dev s1-eth1 root rifo

pifo_load_into_mininet:
	-tc qdisc del dev s1-eth1 root pifo
	-rmmod pifo
	insmod pifo.ko
	tc qdisc add dev s1-eth1 root pifo

sp_pifo_load_into_mininet:
	-tc qdisc del dev s1-eth1 root pifo
	-rmmod pifo
	insmod pifo.ko
	tc qdisc add dev s1-eth1 root pifo

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
