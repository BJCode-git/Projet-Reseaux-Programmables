from utils.utils import generate_network 

# Génère un réseau avec 12 switchs, 4 hôtes et un degré de 3
net = generate_network(12, 4, 3)

# Démarre le réseau
net.startNetwork()