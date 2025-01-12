from utils.utils import generate_network, save_topology
from threading import Thread
from time import sleep

# Génère un réseau avec 12 switchs, 4 hôtes et un degré de 3
net = generate_network(6, 2, 3)

# Démarre le réseau
print("Starting network ...")
t = Thread(target=net.startNetwork)
t.start()
print("Network started ! ")
sleep(10)
save_topology(net,"topology.json")
print("Topology Saved !")
t.join()
