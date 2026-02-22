sjn.o:
	clang -target bpf -g -O2 -c sjn.c -I/usr/include/x86_64-linux-gnu/

sjn_load: sjn.o
	-tc qdisc del dev s1-eth2 clsact
	tc qdisc add dev s1-eth2 clsact
	tc filter add dev s1-eth2 ingress bpf da obj sjn.o
	#   if SEC name is "classifier"
	# tc filter add dev s1-eth2 egress bpf da object-pinned /sys/fs/bpf/marker

srtf.o:
	clang -target bpf -g -O2 -c srtf.c -I/usr/include/x86_64-linux-gnu/

srtf_load: srtf.o
	-tc qdisc del dev s1-eth2 clsact
	tc qdisc add dev s1-eth2 clsact
	tc filter add dev s1-eth2 ingress bpf da obj srtf.o
	#   if SEC name is "classifier"
	# tc filter add dev s1-eth2 egress bpf da object-pinned /sys/fs/bpf/marker
