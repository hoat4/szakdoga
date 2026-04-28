import subprocess

subprocess.run(["ip", "link", "add", "veth1", "type", "veth", "peer", "name", "veth2"], check=True)
subprocess.run(["ip", "link", "set", "veth1", "up"], check=True)
subprocess.run(["ip", "link", "set", "veth2", "up"], check=True)


subprocess.run("tc qdisc add dev veth1 root handle 1: htb default 1".split(), check=True)
subprocess.run(["tc", "class", "add", "dev", "veth1", "parent", "1:", "classid", "1:1", "htb", "rate", "100mbit", "ceil", "100mbit"], check=True)

subprocess.run("tc qdisc add dev veth1 clsact".split(), check=True)

#subprocess.run(["ip", "link", "del", "veth1"], check=True)
