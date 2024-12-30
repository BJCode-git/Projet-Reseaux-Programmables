from networkx import (	Graph,
						random_regular_graph,
						relabel_nodes,
						kamada_kawai_layout,
						planar_layout,
						draw_networkx_nodes , draw_networkx_edges ,
						draw_networkx_labels
					)
from networkx.algorithms.planarity import is_planar
from matplotlib.pyplot import show, close

from p4utils.mininetlib.network_API import NetworkAPI
from p4utils.utils.topology import Topology, NetworkGraph

from random import choice, seed as random_seed , randint
from logging import Logger,getLogger, info, INFO , basicConfig

seed = 1234

def generate_regular_graph(n_switch:int, n_host:int, degree:int) -> Graph:
	"""
	Génère un graphe régulier aléatoire avec 
 	un nombre de switchs, 
	d'hôtes, et degré 
	donnés.
	:param n_switch: Nombre de switchs
	:param n_host: Nombre d'hôtes
	:param degree: Nombre de connexions par switch aux autres switchs
	"""
	global seed
	# Vérification des paramètres
	if n_switch < 3:
		raise ValueError("Le nombre de switchs doit être supérieur à 2.")
	if n_host < 0:
		raise ValueError("Le nombre d'hôtes doit être positif.")
	if degree < 1:
		raise ValueError("Le degré des switchs doit être supérieur à 0.")
	if n_switch * degree % 2 != 0:
		raise ValueError("Le produit n_switch * degree doit être pair.")


	G = random_regular_graph(degree, n_switch, seed=seed)

 	# Modifie le nom des noeuds
	random_seed(seed)
	types = [
				'l', # Loss router
				'd', # Dumb router
				#'n'	 # Normal router
			]
	node_mapping = {}
	for node in G:
		type = 'n'
		# Définit une chance de 1/4 d'avoir un routeur loss ou dumb
		if randint(1,4) == 4:
			# On choisit un type de routeur défectueux
			type = choice(types)
		node_mapping[node] = f"s{type}{node}"
  
	G = relabel_nodes(G, node_mapping)
 
	# On  va modifier le poids des arêtes pour les switchs
	# On va choisir un poids aléatoire entre 1 et 3
	# Cela permettra de simuler des liens de qualité variable
	# Ce qui permettra d'avoir des calculs de chemin plus intéressants
	for edge in G.edges:
		G[edge[0]][edge[1]]['weight'] = randint(1,3)

 
	# Ajout de n_host hôtes
	switch_nodes = list(G.nodes)
	switch_choices = []
	for i in range(0, n_host):
		# On ajoute l'hôte au graphe
		G.add_node(f"h{i}")

		# On choisit un switch auquel connecter l'hôte
	
		# Dans le cas où n_host > n_switch
		# On ajoute des hôtes à des switchs déjà connectés à un hôte
		if len(switch_choices) == 0:
			switch_choices = switch_nodes.copy()

		# On choisit donc un switch
		sw = choice(list(switch_choices))

		# On connecte l'hôte au switch
		G.add_edge(f"h{i}", sw)

		# On retire le switch de la liste des switchs disponibles
		switch_choices.remove(sw)

	return G

def log_graph(graph, logger: Logger = None):
	if logger is None:
		logger = getLogger(__name__)
		basicConfig(level=INFO,format='[%(levelname)s] %(message)s')
		logger.setLevel("INFO")
	
	print(f"Graphe :")
	for node in graph.nodes:
		# On récupère les arêtes du noeud
		print(f" #Noeud '{node}' , Arêtes :")
		edges = list(graph.edges(node,data=True))
		for edge in edges:
			print(f"  |{edge[0]} -> {edge[1]} || {edge[2]}")

def draw_graph(graph):
	try:
		if is_planar(graph):
			pos = planar_layout(graph) # positions for all nodes
		else:
			pos = kamada_kawai_layout(graph) #spring_layout(graph, seed=12)  # positions for all nodes

		options = {"edgecolors": "tab:gray", "node_size": 400, "alpha": 0.9}
		# Position des switchs dans le graphe
		sw_list = [n for n in graph.nodes if n[0] == 's']
		draw_networkx_nodes(graph, pos, nodelist=sw_list, node_color='tab:green', **options)
		
		# Position des hôtes dans le graphe
		host_list = [n for n in graph.nodes if n[0]== 'h']
		draw_networkx_nodes(graph, pos, nodelist=host_list, node_color='tab:blue', **options)

		# Draw edges
		draw_networkx_edges(graph, pos, alpha=0.5, edge_color="tab:red",width=2)

		#labels = {node: graph.nodes[node]['name'] for node in graph.nodes}
		draw_networkx_labels(graph, pos)#, labels=labels)
	except Exception as e:
		raise ValueError(f"Error while drawing the graph: {e}")

	show()
	close()


# Génère une topologie aléatoire 
def generate_network(n_switch:int, n_host:int, degree:int) -> NetworkAPI :
	"""
	Génère une topologie réseau aléatoire avec 
 	un nombre de switchs, 
	d'hôtes, et degré 
	donnés.
	:param n_switch: Nombre de switchs
	:param n_host: Nombre d'hôtes
	:param degree: Nombre de connexions par switch aux autres switchs
	"""
	# Génère le graphe
	G = generate_regular_graph(n_switch, n_host, degree)

	# Affiche le graphe
	print("Graphe généré :")
	log_graph(G)
	draw_graph(G)
 
	net = NetworkAPI()
	
	# Ajoute les switchs / hôtes
	for node in G.nodes:
		if node[0] == 's':
			match node[1]:
				case 'l':
					net.addP4Switch(node,type='simple_router_loss')
				case 'd':
					net.addP4Switch(node,type='simple_router_stupid')
				case _:
					net.addP4Switch(node,type='simple_router')
		elif node[0] == 'h':
			net.addHost(node)

	# Ajout des liens
	for edge in G.edges:
		net.addLink(edge[0],edge[1],weight=G[edge[0]][edge[1]]['weight'])


	net.setP4SourceAll('p4src/simple_router.p4')
 
	# Assignation des adresses IP
	net.l3()
 
	net.enablePcapDumpAll()
	net.enableLogAll()
	net.enableCli()
	net.enableCpuPortAll()
	net.startNetwork() 
	net.save_topology("topology.json")
	
	return net