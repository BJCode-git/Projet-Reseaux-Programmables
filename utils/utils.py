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
#from p4utils.utils.topology import NetworkGraph

from random import choice, seed as random_seed , randint
from logging import Logger,getLogger, INFO, basicConfig , debug, info, warning

# For saving the topology to a JSON file
from networkx.readwrite.json_graph import node_link_data
from p4utils.utils.helper import _prefixLenMatchRegex
import json
from ipaddress import ip_interface, IPv4Network

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


	G : Graph = random_regular_graph(degree, n_switch, seed=seed)

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
		# Définit une chance de 1/5 d'avoir un routeur loss ou dumb
		if randint(1,5) == 1:
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
		G.add_edge(f"h{i}", sw, weight=1)

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


def save_topology(net: NetworkAPI, filename: str):
	"""Saves mininet topology to a JSON file.

	Warning:
		:py:class:`networkx.classes.multigraph.MultiGraph` graphs are not 
		supported yet by :py:class:`~p4utils.utils.topology.NetworkGraph`.
	"""
	# This function return None for each not serializable
	# obect so that no TypeError is thrown.
	def default(obj):
		return None

	
	info('Saving mininet topology to database: {}\n'.format(net.topoFile))

	# Check whether the graph is a multigraph or not
	multigraph = net.is_multigraph()

	if multigraph:
		info('Multigraph topology not supported yet.\n')
	else:
		info('Simple graph topology selected.\n')
		graph = net.g.convertTo(Graph, data=True, keys=False)

		for _, _, params in graph.edges(data=True):

			node1	= params['node1']
			node2	= params['node2']
			edge	= graph[node1][node2]
			params1	= edge.pop('params1', {})
			params2	= edge.pop('params2', {})

			# Save controller cpu interfaces in nodes.
			if node1 == 'sw-cpu' and node2 != 'sw-cpu':
				if graph.nodes[node2]['cpu_port']:
					graph.nodes[node2]['cpu_port_num'] = edge['port2']
					graph.nodes[node2]['cpu_intf'] = edge['intfName2']
					graph.nodes[node2]['cpu_ctl_intf'] = edge['intfName1']
				else:
					raise Exception(
						'inconsistent cpu port for node {}.'.format(node2))
			elif node2 == 'sw-cpu' and node1 != 'sw-cpu':
				if graph.nodes[node1]['cpu_port']:
					graph.nodes[node1]['cpu_port_num'] = edge['port1']
					graph.nodes[node1]['cpu_intf'] = edge['intfName1']
					graph.nodes[node1]['cpu_ctl_intf'] = edge['intfName2']
				else:
					raise Exception(
						'inconsistent cpu port for node {}.'.format(node1))

			# Move outside parameters in subdictionaries
			# and append number to identify them.
			for key in params1.keys():
				edge[key+'1'] = params1[key]

			for key in params2.keys():
				edge[key+'2'] = params2[key]

			# Fake switches' IPs
			if 'sw_ip1' in edge.keys():
				edge['ip1'] = edge['sw_ip1']
				del edge['sw_ip1']

			if 'sw_ip2' in edge.keys():
				edge['ip2'] = edge['sw_ip2']
				del edge['sw_ip2']
				
			# Get addresses from the network
			# This gathers also routers interfaces IPs!
			# virtual switch ips start with 20.x.x.x for the sake of it
			# we will consider those Ips as reserved and not update them
			# we need to check if they are P4 switches and not remove the IP.
			try:
				port1 = edge['port1']
				#info('Updating address for node {} port {}.\n'.format(node1, port1))
				print(net.net)
				intf1 = net.net[node1].intfs[port1]
				ip1, addr1 = intf1.updateAddr()
				#import ipdb; ipdb.set_trace()
				if ip1 is not None:
					subnet1 = _prefixLenMatchRegex.findall(intf1.ifconfig())[0]
					ip1 = ip_interface(ip1+'/'+subnet1).with_prefixlen
					# possible bug: I moved this here so switches do not lose the virtual ip
					edge.update(ip1=ip1, addr1=addr1)

				port2 = edge['port2']
				intf2 = net.net[node2].intfs[port2]
				ip2, addr2 = intf2.updateAddr()
				#import ipdb; ipdb.set_trace()
				if ip2 is not None:
					subnet2 = _prefixLenMatchRegex.findall(intf2.ifconfig())[0]
					ip2 = ip_interface(ip2+'/'+subnet2).with_prefixlen
					# possible bug: I moved this here so switches do not lose the virtual ip
					edge.update(ip2=ip2, addr2=addr2)
			except Exception as e:
				warning('save_topology : error updating addresses -> {}\n'.format(e))

		# Remove sw-cpu if present
		if 'sw-cpu' in graph:
			graph.remove_node('sw-cpu')

	graph_dict = node_link_data(graph)

	# save topology locally
	with open(net.topoFile, 'w') as f:
		json.dump(graph_dict, f, default=default)

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
	net.setLogLevel("info")
	
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
 
	

	# Ajoute les liens
	for edge in G.edges.data("weight", default=1):
		if edge[0] in net.nodes() and edge[1] in net.nodes():
			print(f"Adding link: {edge[0]} <-> {edge[1]} with weight {edge[2]}")
			try:
				net.addLink(edge[0], edge[1], weight=edge[2])
			except Exception as e:
				print(f"Error while adding link: {e}")
			except:
				print(f"Error while adding link.")
		else:
			print(f"Skipping invalid link: {edge[0]} <-> {edge[1]}")

  
	# Ajout des pertes pour les routeurs de type loss
	#for edge in net.links():
	#	if net.getNode(edge[0])['type'] == 'simple_router_loss':
	#		net.setLoss(edge[0],edge[1],0.3)

	
	
	
	# Assignation des adresses IP
	net.l3()
	
	net.setP4SourceAll('p4src/simple_router.p4')
	net.compile()
	net.enablePcapDumpAll()
	net.enableLogAll()
	net.enableCli()
	net.enableCpuPortAll()
	# Assignation automatique des adresses IP
	net.auto_assignment()
	
	

	print("Is multigraph ? : ", net.is_multigraph())
 
	print("Nodes:")
	for n in net.nodes():
		if(net.isP4Switch(n)):
			match net.getNode(n)['type']:
				case 'simple_router_loss':
					print(f"{n} (Loss router)")
				case 'simple_router_stupid':
					print(f"{n} (Dumb router)")
				case _:
					print(f"{n} (Normal router)")
		else:
			print(f"{n}")
	
	print("Liens:")
	for arcs in net.links():
		print(f"{arcs[0]} -> {arcs[1]}")
 
	# Affiche les ports et interfaces
	print("Ports:")
	for n,ports in net.node_ports().items():
		print(f" {n} :")
		for port in ports:
			print(f"  {port} : {ports[port]} ")
  
	print("Interfaces:")
	for n,intfs in net.node_intfs().items():
		print(f" {n} :")
		for intf in intfs:
			print(f"  {intf} : {intfs[intf]} ")

	print("Topologie générée. !!!")


	#net.startNetwork()
	# Sauvegarde la topologie
	#save_topology(net, "topology.json")

	return net