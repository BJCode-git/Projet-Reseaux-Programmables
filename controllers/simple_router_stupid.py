import os
import json

import networkx as nx

from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from p4utils.mininetlib.network_API import NetworkAPI
from p4utils.utils.compiler import P4C
from p4utils.utils.helper import load_topo

from random import choice

from logging import getLogger, INFO, DEBUG, ERROR, WARNING, StreamHandler, Formatter

from simple_router import SimpleRouter



class SimpleRouterStupid(SimpleRouter):
	"""
	Un routeur simple capable de faire du routage.
	Calqué sur le SimpleRouter, mais avec une méthode de routage stupide.
	Il utilise des chemins aléatoires au lieu des plus courts chemins,
 	(afin de simuler un équipement corrumpu)."""

	def __init__(self, 
				name : str,
				topology_file="topology.json", 
				p4src="p4src/simple_router.p4",
				log_level = INFO):
		super().__init__(name, topology_file, p4src)

		# Configuration du logger
		self.__logger.name = "SimpleRouterStupid"

	def __compute_routes(self):
		""" 
		Méthode  override de SimpleRouter.
		Calcule les routes de façon stupide.
		On prend pour chaque destination, un chemin aléatoire.
		"""
		# Récupération de la topologie
		graph = self.__topology

		# Calcul et ajout des routes
		# Calcul de tous les plus courts chemins
		for dest in graph.nodes():
			if dest == self.__name:
				continue
			paths = nx.all_simple_paths(graph, self.__name, dest)
			if len(paths) == 0:
				continue
			self.__routing_table[dest] = choice(list(paths))

	def set_route(self,dest_host : str, route:list):
		"""
		Spécifie une route lien par lien.
		"""
  
		# On regarde si la destination est bien dans la topologie
		if  not self.__topology.checkNodes(dest_host):
			raise ValueError("La destination n'est pas dans la topologie.")

		# On regarde si la route arrive bien à la destination
		if route[-1] != dest_host:
			raise ValueError("La route ne contient pas la destination.")

		# On regarde s'il existe bien un chemin entre le routeur et la destination
		if not nx.has_path(self.__topology,self.__name,dest_host):
			raise Exception("La route n'est pas valide.")
		
		# On définit la route
		self.__routing_table[dest_host] = route
  
		# On ajoute la route dans la table de routage
		self.__logger.info(f"Ajout de la route {route} pour {dest_host}")

		# On installe la règle vers le prochain saut
		next_hop_ip		= self.__topology.get_host_ip(route[1])
		next_hop_mac	= self.__topology.get_host_mac(route[1])
		next_hop_port	= self.__topology.get_port(self.__name, route[1])
  
		# On installe la règle vers le prochain saut
		# table_name , action_name , match_fields , action_params
		self.__controller.table_add("ipv4_lpm",[f"{next_hop_ip}/32"],[str(next_hop_port)],str(next_hop_mac))

