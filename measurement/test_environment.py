import subprocess

subprocess.run(["ip", "link", "add", "veth1", "type", "veth", "peer", "name", "veth2"], check=True)
subprocess.run(["ip", "link", "set", "veth1", "up"], check=True)
subprocess.run(["ip", "link", "set", "veth2", "up"], check=True)

#subprocess.run(["ip", "link", "del", "veth1"], check=True)
