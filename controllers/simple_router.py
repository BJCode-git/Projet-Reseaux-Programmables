"""
Un router simple capable de faire du routage.
Cet équipement est composé d’un plan de données P4, 
mais également d’un plan de contrôle python en charge du calcul
des meilleurs chemins et de l’installation des entrées pertinentes dans les tables.
"""

import os
import json
from collections import defaultdict

## Import des modules pour le routage ##
import networkx as nx
from networkx.algorithms import all_pairs_dijkstra

## Import des modules P4utils ##
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from p4utils.utils.compiler import P4C
from p4utils.utils.helper import load_topo
from p4utils.utils.topology import Topology, NetworkGraph

## Import des modules de communication ##
from scapy.all import sendp, Ether, IP


from logging import getLogger, INFO, DEBUG, ERROR, WARNING, StreamHandler, Formatter



class SimpleRouter:
	"""
	Un routeur simple capable de faire du routage.
	Cet équipement est composé d’un plan de données P4,
	mais également d’un plan de contrôle python en charge du calcul
	des meilleurs chemins et de l’installation des entrées pertinentes dans les tables.
	"""
	def __init__(self, 
				name : str,
				topology :str | NetworkGraph = "topology.json",
				p4src : str = "p4src/simple_router.p4",
				log_level = INFO):
		"""
		Initialise le contrôleur avec la topologie réseau.
		"""
		if isinstance(topology,str) and not os.path.exists(topology):
			raise FileNotFoundError(f"Le fichier de topologie n'existe pas au chemin spécifié : {topology}")
		elif not os.path.exists(p4src):
			raise FileNotFoundError(f"Le fichier P4 n'existe pas au chemin spécifié : {p4src}")


		# Compilation du code P4
		src = P4C(p4src,"usr/local/bin/p4c")
		src.compile()

		# Identifiant du switch
		self.__name: str						= name
		# Chargement de la topologie
		if isinstance(topology,str):
			self.__topology: NetworkGraph		= load_topo(topology)
		elif isinstance(topology,NetworkGraph):
			self.__topology: NetworkGraph		= topology
		# Interface pour contrôler les équipements P4
		self.__controller						= SimpleSwitchThriftAPI(self.topology.get_thrift_port(name))
		# Table de routage
		self.__routing_table:defaultdict[list]	= defaultdict(list)
		## Supervision des liens et des chemins ##
		# Table de liens reçus
		self.__received_links:list[int]			= list(int)
		# Table des chemins reçus 
		self.__received_paths:defaultdict[list]	= defaultdict(list)
  
		## Variables des registres du contrôleur ##
  
		# Définition du taux de perte à 0 par défaut
		self.__loss_rate					= 0
		# Définition du nombre de paquets perdus à 0 par défaut
		self.__total_packets_lost			= 0
		# Définition du nombre de paquets sondes envoyés à 0 par défaut
		self.__total_probe_packets_sent		= 0
		# Définition du nombre de paquets sondes revenus à 0 par défaut
		self.__total_probe_packets_returned	= 0


		# Configuration du logger
		self.__logger = getLogger("SimpleRouter")
		self.__logger.setLevel(log_level)
		ch = StreamHandler()
		ch.setLevel(log_level)
		ch.setFormatter(Formatter('[%(levelname)s]: %(name)s - %(message)s'))
		self.__logger.addHandler(ch)
  
		# Initialisation des registres, et des tables
		self.init_all()

	def __compute_routes(self):
		"""
		Calcule les routes pour chaque switch de la topologie.
		"""
		# Récupération de la topologie
		graph = self.__topology
  
		# Calcul des plus courts chemin depuis le switch actuel.
		paths = nx.shortest_path(graph,source=self.__name)
  
		# On étend la table de routage avec les chemins
		self.__routing_table.update(paths)
  
		# On log les routes calculées
		self.__logger.debug(f"Table de routage calculée : ")
		if self.__logger.isEnabledFor(DEBUG):
			for dest in self.__routing_table:
				self.__logger.debug(f"Destination {dest} : {self.__routing_table[dest]}")

	def __install_next_hops(self):
		"""
		Installe les prochains sauts pour chaque destination.
		"""
		# On récupère les hotes accessibles depuis le switch actuel
		for dest_name in self.__routing_table:

			# On récupère le prochain saut
			next_hop = self.__routing_table[dest_name][1]

			# On vérifie que le prochain est bien un voisin
			if not self.__topology.is_neighbor(self.__name,next_hop):
				self.__logger.error(f"Le prochain saut {next_hop} n'est pas un voisin du switch {self.__name} !!")
				raise Exception(f"Le prochain saut {next_hop} n'est pas un voisin du switch {self.__name}")

			# On récupère l'ip du prochain saut
			next_hop_ip = self.__topology.node_to_node_ip(next_hop,self.__name)
			# On récupère le port de sortie
			next_hop_port = self.__topology.node_to_node_port_num(self.__name,next_hop)
			# On récupère l'adresse mac du prochain saut
			next_hop_mac = self.__topology.node_to_node_mac(next_hop,self.__name)
			# On récupère l'ip du prochain saut

			# On installe la règle vers le prochain saut
			# table_name , action_name , match_fields , action_params
			self.__controller.table_add("ipv4_lpm",[f"{dest_name}/32"],[str(next_hop_port)],str(next_hop_mac))

	def __install_multicast(self):
		"""
		Installe les règles de multicast.
		cf : https://github.com/nsg-ethz/p4-learning/blob/master/exercises/03-L2_Flooding/thrift/solution/switch_controller.py
		"""
		# On cherche à créer un groupe multicast unique pour l'ensemble des switchs
		# Ce groupe a l'id 1, cela permet de broadcast à tous les switchs les sondes

		# On récupère les ports 
		interfaces_to_port = self.__topology.get_node_intfs(self.__name,fields="port")
		# On envoie sur tous les ports
		ports = [int(intf) for intf in interfaces_to_port.values()]
		# On retire le port CPU de la liste des ports du groupe multicast
		ports.remove(self.__topology.get_cpu_port_index(self.__name))
  
		# On crée le groupe multicast d'id 1 sur tous les ports
		self.__controller.mc_mgrp_create(1, ports)	

	def __install_ip_and_mac(self):
		"""
		Installe l'adresse MAC, IP, et le port cpu du switch actuel.
		"""
		# On récupère les adresses MAC et IP des switchs
		switch_mac		= self.__topology.get_node_mac(self.__name)
		switch_ip		= self.__topology.get_node_ip(self.__name)
		switch_cpu_port	= self.__topology.get_cpu_port_index(self.__name)
  
		# On installe les informations du switch dans la table
		self.__controller.table_add("router_info",["set_router_info"],[],[switch_mac,switch_ip,switch_cpu_port])


	def __update_mininet(self):
		"""
		Met à jour la topologie Mininet.
		"""
		self.__logger.debug("Mise à jour de la topologie Mininet...")

		self.__controller.switch_info.load_json_config(self.__controller.client)
		self.__controller.table_entries_match_to_handle = self.__controller.create_match_to_handle_dict()
		self.__controller.load_table_entries_match_to_handle()
  
		self.__logger.debug("Topologie Mininet mise à jour avec succès.")

	def update_topology(self, topology:str | NetworkGraph):
		"""
		Met à jour la topologie.
		"""
		self.__logger.debug("Mise à jour de la topologie...")
  
		if isinstance(topology,NetworkGraph):
			self.__topology = topology
			self.__update_mininet()

		elif isinstance(topology,str):
			if not os.path.exists(topology):
				raise FileNotFoundError(f"Le fichier de topologie n'existe pas au chemin spécifié : {topology}")
			self.__topology = load_topo(topology)
  
		# On réinitialise les tables, et l'état du contrôleur
		self.reset()
  
		# On recalcule les routes, et on les installe
		self.run()
  
		self.__logger.debug("Topologie mise à jour avec succès.")
  
 
	##### Méthodes pour gérer les registres #####
 
	# Pour obtenir "total_packets_lost" par exemple, on fait :
	# controller.register_read("total_packets_lost", 0)
	# -> read_register("total_packets_lost", 0)
 
	def read_register(self, register_name:str, index : int | None  = None):
		"""
		_param register_name : str : Nom du registre à lire.
		_param index : int : Index du registre à lire.

		Lit la valeur d'un registre. 
		"""

		value = self.__controller.register_read(register_name, index)
		self.__logger.debug(f"Valeur(s) lue(s) dans le registre {register_name}: {value}")

		# On met à jour la valeur du registre
		match register_name:
			case "loss_rate":
				self.__loss_rate = value
			case "total_packets_lost":
				self.__total_packets_lost = value
			case "total_probe_packets_sent":
				self.__total_probe_packets_sent = value
			case "total_probe_packets_returned":
				self.__total_probe_packets_returned = value
			case _:
				pass

		return value

	def write_register(self, register_name:str , value , index:int | list | None = None):
		"""
		_param register_name : str : Nom du registre à écrire.
		_param value : Any : Valeur à écrire dans le registre.
		_param index : int | list | None : Index du registre à écrire.

		Ecrit une valeur dans un registre.
		"""
		if index is None:
			index = 0
	
		self.__controller.register_write(register_name, index, value)
	
		# On met à jour la valeur du registre
		match register_name:
			case "loss_rate":
				self.__loss_rate = value
			case "total_packets_lost":
				self.__total_packets_lost = value
			case "total_probe_packets_sent":
				self.__total_probe_packets_sent = value
			case "total_probe_packets_returned":
				self.__total_probe_packets_returned = value
			case _:
				pass
  
		self.__logger.debug(f"Valeur {value} écrite dans le registre {register_name} à l'index {index}.")
	
	def reset_registers(self):
		"""
		Réinitialise tous les registres du contrôleur.
		"""
		self.__controller.reset_registers()

		# On met à jour les valeurs des registres
		self.__loss_rate					= 0
		self.__total_packets_lost			= 0
		self.__total_probe_packets_sent		= 0
		self.__total_probe_packets_returned	= 0
  
		# On remet les valeurs des registres à 0
		self.__overwrite_all_registers()
  
		self.__logger.debug("Registres réinitialisés avec succès.")

	def get_register_arrays(self):
		"""
		Récupère les registres du contrôleur.
		"""
		return self.__controller.get_register_arrays()

	def __overwrite_all_registers(self):
		"""
		Ecrit les valeurs du contrôleur dans les registres.
		"""
		self.write_register("loss_rate", 0, self.__loss_rate)
		self.write_register("total_packets_lost", 0, self.__total_packets_lost)
		self.write_register("total_probe_packets_sent", 0, self.__total_probe_packets_sent)
		self.write_register("total_probe_packets_returned", 0, self.__total_probe_packets_returned)
		self.__logger.debug("Registres écrits avec succès.")

	def __update_all_registers(self):
		"""
		Lit les valeurs des registres du contrôleur.
		"""

		self.__logger.debug("Lecture des registres...")
 
		self.__loss_rate					= self.read_register("loss_rate", 0)
		self.__total_packets_lost			= self.read_register("total_packets_lost", 0)
		self.__total_probe_packets_sent		= self.read_register("total_probe_packets_sent", 0)
		self.__total_probe_packets_returned	= self.read_register("total_probe_packets_returned", 0)

		self.__logger.debug("Registres lus avec succès.")

	##### Méthodes pour gérer les tables #####

	def install_entry(self,table_name:str, entry ):
		"""
		_param table_name : str : Nom de la table.
		_param entry : Any : Entrée à installer.

		Installe une entrée dans une table.
		"""
		self.__controller.table_add(table_name, entry)

	def remove_entry(self,table_name:str, entry ):
		"""
		_param table_name : str : Nom de la table.
		_param entry : Any : Entrée à supprimer.

		Supprime une entrée dans une table.
		"""
		self.__controller.table_delete_match(table_name, [str(entry)])


	##### Méthodes globales pour intialiser/ réinitialiser le contrôleur #####

	def init_all(self):
		"""
		Calcule les routes,
		installe les entrées dans les tables,
		et initialise les registres.
		"""
		self.__logger.info("Initialisation des tables...")

		# On met à jour la topologie connue par le contrôleur
		self.__update_mininet()
		# On établit tout à 0 (notamment les registres)
		self.reset()
		# On calcule les routes
		self.__compute_routes()
		# On installe les routes dans les tables
		self.__install_next_hops()
		# On installe les règles de multicast
		self.__install_multicast()
		# On installe les informations du switch
		self.__install_ip_and_mac()
  
		self.__logger.info("Routes installées avec succès.")

	def reset(self):
		"""
		Nettoie les tables de routage, et réinitialise l'état du contrôleur.
		"""
		self.__controller.reset_state()	
  
  ##### Méthodes pour la supervision du contrôleur #####
  
	def __send_links_probe_packet(self):
		"""
		Envoie un paquet de sonde pour tester les liens voisins.
		"""
		# On envoie un paquet de type probe sur le port CPU
		self.__controller.
	
	def __send_paths_probe_packet(self):
		"""
		Envoie un paquet de sonde pour tester les chemins.
		"""
		# On envoie un paquet de type probe sur le port CPU
		# Et ce, pour chaque destination de la table de routage
		origin_ip = self.__topology.get_node_ip(self.__name)
		for dest in self.__routing_table:
			self.__controller.
	
	def send_probes(self):
		"""
		Envoie des sondes sur les liens et les chemins.
		"""
		self.send_links_probe_packet()
		self.send_paths_probe_packet()
	