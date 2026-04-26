all: sjn.o srtf.o

sjn.o: sjn.c
	clang -target bpf -g -O2 -c sjn.c -I/usr/include/x86_64-linux-gnu/

sjn_load: sjn.o
	-tc qdisc del dev s1-eth2 clsact
	tc qdisc add dev s1-eth2 clsact
	tc filter add dev s1-eth2 ingress bpf da obj sjn.o

srtf.o: srtf.c
	clang -target bpf -g -O2 -c srtf.c -I/usr/include/x86_64-linux-gnu/

srtf_load: srtf.o
	-tc qdisc del dev s1-eth2 clsact
	tc qdisc add dev s1-eth2 clsact
	tc filter add dev s1-eth2 ingress bpf da obj srtf.o

clean: 
	rm *.o *.o.tmp
