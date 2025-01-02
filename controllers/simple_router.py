"""
Un router simple capable de faire du routage.
Cet équipement est composé d’un plan de données P4, 
mais également d’un plan de contrôle python en charge du calcul
des meilleurs chemins et de l’installation des entrées pertinentes dans les tables.
"""

import os
from collections import defaultdict
from typing import Any

## Import des modules P4utils ##
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from p4utils.utils.compiler import P4C
from p4utils.utils.helper import load_topo
from p4utils.utils.topology import NetworkGraph #, Topology

## Import des modules de communication ##
from scapy.all import Ether, IP, sendp , Packet, BitField, FieldListField, sniff
from ipaddress import IPv4Address

# Import pour les threads
from threading import Thread

# Import pour les logs
from logging import getLogger, INFO, DEBUG, ERROR, WARNING, StreamHandler, Formatter


PROTOCOL_LINK_TEST_TRIGGER	= 0x95
PROTOCOL_PATH_TEST_TRIGGER	= 0x98
PROTOCOL_PATH_TEST_RETURN	= 0x9A

class CustomRoute(Packet):
	"""
	En-tête custom_route_t pour enregistrer les sauts intermédiaires.
	"""
	name = "CustomRoute"
	fields_desc = [
		BitField("last_header", 0, 8),  # Flag indiquant le dernier saut
		BitField("hop", 0, 32),        # Adresse IP du routeur
	]

class ProbeReturnHeader(Packet):
	"""
	Header d'un paquet retourné au contrôleur avec une liste de routeurs traversés.
	"""
	name = "ProbeReturnHeader"
	fields_desc = [
		FieldListField("custom_route", [], CustomRoute, length_from=lambda pkt: pkt.ihl)
	]


## Construire un paquet de test
#packet = (
#    Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55", type=0x0800) /
#    IP(src="10.0.0.1", dst="10.0.0.2", proto=0x9A) /
#    ProbeReturnHeader(custom_route=[
#        CustomRoute(last_header=0, hop=0xC0A80101),  # 192.168.1.1
#        CustomRoute(last_header=1, hop=0xC0A80102),  # 192.168.1.2
#    ])
#) 

class Stats:
	"""
	Classe pour stocker les statistiques du contrôleur.
	total_packets_lost : Nombre total de paquets perdus.
	total_probe_packets_sent : Nombre total de paquets sondes envoyés.
	total_probe_packets_returned : Nombre total de paquets sondes revenus.
	down_ports : Liste des ports down.
	wrong_paths : Liste de paires de chemins :
		Avec le chemin optimal, et le chemin réellement emprunté.
	"""
	total_packets_lost:				int 								= 0
	total_probe_packets_sent:		int 								= 0
	total_probe_packets_returned:	int									= 0
	down_ports:						list[int]							= []
	wrong_paths:					list[tuple[list[str],list[str]]]	= []

class SimpleRouter:
	"""
	Un routeur simple capable de faire du routage.
	Cet équipement est composé d’un plan de données P4,
	mais également d’un plan de contrôle python en charge du calcul
	des meilleurs chemins et de l’installation des entrées pertinentes dans les tables.
	Liste des tables :
	- ipv4_lpm : Table de routage. 
		-> Actions : 
			- ipv4_forward : Routage des paquets. 
		- no_routing_action : Pas de routage. Ajout de statistiques.
	- router_info : Table d'informations sur le routeur.
		-> Actions : 
			- set_router_info : Ajout des informations du routeur.
	Liste des registres disponibles : 
		- loss_rate : Taux de perte des paquets.
		- total_packets_lost : Nombre total de paquets perdus.
		- total_probe_packets_sent : Nombre total de paquets sondes envoyés.
		- total_probe_packets_returned : Nombre total de paquets sondes revenus.
		- active_ports : Liste des ports actifs.
		- active_ports_size : Nombre de ports actifs.
	"""
 
	def __init__(self,
				name : str,
				topology :str | NetworkGraph = "topology.json",
				p4src : str = "p4src/simple_router.p4",
				log_level = INFO):
		"""
		Initialise le contrôleur avec la topologie réseau.
		_param name : str : Nom du switch.
		_param topology : str | NetworkGraph : Graphe ou Chemin vers le fichier json pour charger la topologie réseau.
		_param p4src : str : Chemin vers le fichier P4.
		_param log_level : int : Niveau de log.
		"""
		if isinstance(topology,str) and not os.path.exists(topology):
			raise FileNotFoundError(f"Le fichier de topologie n'existe pas au chemin spécifié : {topology}")
		elif not os.path.exists(p4src):
			raise FileNotFoundError(f"Le fichier P4 n'existe pas au chemin spécifié : {p4src}")


		# Compilation du code P4
		#src = P4C(p4src,"usr/local/bin/p4c")
		#src.compile()

		# Identifiant du switch
		self.__name: str						= name
  
		# Chargement de la topologie
		if isinstance(topology,str):
			self.__topology: NetworkGraph		= load_topo(topology)
		elif isinstance(topology,NetworkGraph):
			self.__topology: NetworkGraph		= topology

		# Interface pour contrôler les équipements P4
		self.__controller						= SimpleSwitchThriftAPI(self.__topology.get_thrift_port(name))
		# Table de routage
		self.__routing_table:defaultdict[list]	= defaultdict(list)
		## Supervision des liens et des chemins ##
		# Table de liens fonctionnels
		self.__links_up:list[int]				= list(int)
		# Table des chemins empruntés par les sondes 
		self.__received_paths:defaultdict[list]	= defaultdict(list)
  
		# Thread pour la capture des paquest sur le port CPU
		self.__sniff_running					= False
		self.__sniff_thread						= None

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
		Calcule les plus courts chemins pour chaque destination de la topologie.
		"""
		# Pour chaque noeud de la topologie,
		# On calcule le plus court chemin depuis le switch actuel
		for dest in self.__topology.get_nodes():
			# Si la destination est le switch actuel (on 2 noeuds identiques : source et destination)
			if dest == self.__name:
				path = [self.__name,self.__name]
			else:
				# Calcul du plus court chemin depuis le switch actuel
				path		 = self.__topology.get_shortest_paths_between_nodes(self.__name,dest)
				# La liste recu contient la liste des liens à emprunter, on va garder que les noms des switchs
				path		 = [link[1] for link in path]
			# On rajoute le switch actuel à la liste en début de chemin
			path.insert(0,self.__name)
			# On étend la table de routage avec les chemins
			self.__routing_table[dest] = path
			
		# On log les routes calculées
		self.__logger.debug(f"Table de routage calculée : ")
		if self.__logger.isEnabledFor(DEBUG):
			for dest in self.__routing_table:
				self.__logger.debug(f"Destination {dest} : {self.__routing_table[dest]}")

	def __install_next_hops(self):
		"""
		Installe les prochains sauts pour chaque destination.
		"""
		
		# Pour chaque destination de la table de routage
		for dest_name in self.__routing_table:
			
			# Si la destination est le switch actuel, on ne fait rien
			if dest_name == self.__name:
				self.__topology.get_hos

			# On récupère le nom du prochain noeud
			next_hop = self.__routing_table[dest_name][1]

			# On vérifie que le prochain est bien un voisin
			if not self.__topology.is_neighbor(self.__name,next_hop):
				self.__logger.error(f"Le prochain saut {next_hop} n'est pas un voisin du switch {self.__name} !!")
				raise Exception(f"Le prochain saut {next_hop} n'est pas un voisin du switch {self.__name}")

			# On récupère le port de sortie du switch vers le prochain saut
			next_hop_port = self.__topology.node_to_host_port_num(self.__name,next_hop)
			# On récupère l'adresse mac du prochain saut
			next_hop_mac = self.__topology.node_to_host_mac(next_hop,dest_name)

			# Si le noeud de destination est un hôte :
			if self.__topology.isHost(dest_name):
				# On récupère l'ip de l'hôte de destination
				host_ip = self.__topology.get_host_ip(dest_name)
				next_hop_ip = self.__topology.node_to_node_interface_ip(self.__name,next_hop)
			
				# On installe la règle vers l'hôte
				#  ipv4_lpm , ipv4_forward , ip_dst -> port , mac, next_hop_ip_src
				self.__controller.table_add(
											"ipv4_lpm",
											"ipv4_forward" ,
											[f"{host_ip}/24"],
											[str(next_hop_port) ,str(next_hop_mac), str(next_hop_ip)])

			# Maintenant, si le noeud de destination est un switch
			else :
				# On va ajouter l'ip de la destination sur l'interface finale

				# On récupère l'ip de la destination sur l'interface finale
				# Soit l'ip  de dest sur l'interface entre [dest-1] et [dest]

				switch_ip	= self.__topology.node_to_node_interface_ip(dest_name,self.__routing_table[dest_name][-2])
				next_hop_ip = self.__topology.node_to_node_interface_ip(self.__name,next_hop)
				# On récupère l'ip du prochain saut

				# On installe la règle vers le prochain saut
				# On installe la règle vers l'hôte
				#  ipv4_lpm , ipv4_forward , ip_dst -> port , mac, next_hop_ip
				self.__controller.table_add("ipv4_lpm",
											"ipv4_forward",
											[f"{switch_ip}"],
											[str(next_hop_port),str(next_hop_mac), str(next_hop_ip)], 
											priority=1)
	
	def __install_multicast(self):
		"""
		Installe les règles de multicast.
		Permet de broadcast les sondes de liens sur tous les ports du switch.
		cf : https://github.com/nsg-ethz/p4-learning/blob/master/exercises/03-L2_Flooding/thrift/solution/switch_controller.py
		"""
		# On cherche à créer un groupe multicast unique pour l'ensemble des switchs
		# Ce groupe a l'id 1, cela permet de broadcast à tous les switchs les sondes

		# On récupère les ports du routeur
		interfaces_to_port = self.__topology.get_node_intfs(fields="port")[self.__name]
		# On envoie sur tous les ports
		ports = [int(intf) for intf in interfaces_to_port.values()]
		# On retire le port CPU de la liste des ports du groupe multicast
		ports.remove(self.__topology.get_cpu_port_index(self.__name))
  
		# On crée le groupe multicast d'id 1
		self.__controller.mc_mgrp_create(1)
		# On ajoute les ports au noeud multicast
		handle = self.__controller.mc_node_create(1, ports)
		# On associe le noeud multicast au groupe multicast
		self.__controller.mc_node_associate(1, handle)
	
	def __install_router_info(self):
		"""
		Installe  le port cpu du switch dans le registre cpu_port,
		Et installe les ip du switch dans la table router_info.
		"""
		# On récupère les adresses MAC et IP des switchs

		switch_cpu_port	 = self.__topology.get_cpu_port_index(self.__name)
		self.write_register("cpu_port", switch_cpu_port, 0)

		## On installe les informations du switch dans la table
		for n in self.__topology.get_neighbors(self.__name):
			switch_ip = self.__topology.node_to_node_interface_ip(self.__name,n)
			ip = f"{switch_ip}/24"
			self.__controller.table_add("router_info",["set_router_info"],[ip],[])

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
		_param topology : str | NetworkGraph : Chemin vers le fichier json pour charger la topologie réseau, ou la topologie réseau.
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

		# On recalule les routes, 
		# et on réinstalle toutes les entrées et les informations du switch
		self.init_all()

		self.__logger.debug("Topologie mise à jour avec succès.")


	##### Méthodes pour gérer les registres #####
 
	# Pour obtenir "total_packets_lost" par exemple, on fait :
	# controller.register_read("total_packets_lost", 0)
	# -> read_register("total_packets_lost", 0)
 
	def read_register(self, register_name:str, index : int | None  = None) -> Any | list[Any]:
		"""
		Lit la valeur d'un registre.
		_param register_name : str : Nom du registre à lire.
		_param index : int : Index du registre à lire.
		Si None, lit tout le tableau du registre.
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

		# On met à jour les valeurs des registres
		self.__loss_rate					= 0
		self.__total_packets_lost			= 0
		self.__total_probe_packets_sent		= 0
		self.__total_probe_packets_returned	= 0
		self.__links_up						= []
  
		# On remet les valeurs des registres à 0
		self.__controller.register_reset("loss_rate")
		self.__controller.register_reset("total_packets_lost")
		self.__controller.register_reset("total_probe_packets_sent")
		self.__controller.register_reset("total_probe_packets_returned")
		self.__controller.register_reset("links_up")

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
		self.write_register("links_up", self.__links_up,[0,len(self.__links_up)])
		self
		self.__logger.debug("Registres écrits avec succès.")

	def __update_all_registers(self):
		"""
		Lit les valeurs des registres du contrôleur,
		Et met à jour les attributs du contrôleur.
		"""

		self.__logger.debug("Lecture des registres...")
 
		self.__loss_rate					= self.read_register("loss_rate", 0)
		self.__total_packets_lost			= self.read_register("total_packets_lost", 0)
		self.__total_probe_packets_sent		= self.read_register("total_probe_packets_sent", 0)
		self.__total_probe_packets_returned	= self.read_register("total_probe_packets_returned", 0)
		self.__links_up						= self.__controller.register_read("links_up", None)

		self.__logger.debug("Registres lus avec succès.")

	##### Méthodes pour gérer les tables #####

	def install_entry(self,table_name:str, action_name :str,match_keys : list,action_params :list = []):
		"""
		_param table_name : str : Nom de la table.
		_param entry : Any : Entrée à installer.

		Installe une entrée dans une table.
		"""
		self.__controller.table_add(table_name, action_name,match_keys,action_params)

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
		self.__install_router_info()

		self.__logger.info("Routes installées avec succès.")

	def reset(self):
		"""
		Nettoie les tables de routage, et réinitialise l'état du contrôleur.
		"""
		self.__controller.reset_state()	
  
  ##### Méthodes pour la supervision du contrôleur #####
  
   ### Méthodes pour l'envoi des sondes ###

	def __send_probe_trigger_packet(self,protocol: int, dest:str | None = None):
		"""
		Envoie un paquet de sonde pour tester les liens voisins.
		_param protocol : int : Protocole du paquet de sonde.
		_param dest : str | None : Destination du paquet de sonde.
		Doit être PROTOCOL_LINK_TEST_TRIGGER (0x95) ou PROTOCOL_PATH_TEST_TRIGGER (0x98).
		"""
		global PROTOCOL_LINK_TEST_TRIGGER, PROTOCOL_PATH_TEST_TRIGGER
  
		if protocol not in [PROTOCOL_LINK_TEST_TRIGGER, PROTOCOL_PATH_TEST_TRIGGER]:
			raise ValueError(f"Le protocole {protocol} n'est pas supporté.")
		
		# On construit le paquet de sonde
		src_mac	= self.__topology.get_nodes()[self.__name]["mac"]
		if protocol == PROTOCOL_LINK_TEST_TRIGGER or dest is None:
			# Adresse MAC de broadcast
			dest_mac = "ff:ff:ff:ff:ff:ff"
		else:
			dest_mac= self.__topology.get_nodes()[dest]["mac"]
  
		src_ip	= self.__topology.get_nodes()[self.__name]["ip"]
		dest_ip	= self.__topology.get_nodes()[dest]["ip"]
	
		probe_packet = Ether(	src=src_mac,
								dest=dest_mac ) /IP(src=src_ip,
									dst=dest_ip,
									proto=protocol)
	
		# On récupère l'interface cpu et le port cpu
		cpu_intf = self.__topology.get_cpu_port_intf(self.__name)
		cpu_port = self.__topology.get_cpu_port_index(self.__name)

		# On envoie le paquet de sonde
		sendp(probe_packet, iface=cpu_intf, port=cpu_port)

	def send_probes(self):
		"""
		Envoie des sondes sur les liens et les chemins.
		"""
		self.__send_probe_trigger_packet(PROTOCOL_LINK_TEST_TRIGGER)

		# On envoie des sondes de chemin vers tous les switchs
		# En parallèle, on va écouter les réponses des sondes de chemin sur le port CPU
		for dest in self.__routing_table:
			# On ne s'intéresse pas aux hôtes, ou à soi-même
			# on ne peut encapsuler une sonde retour vers un hôte
			if self.__topology.isHost(dest) or dest == self.__name:
				continue
			self.__send_probe_trigger_packet(PROTOCOL_PATH_TEST_TRIGGER, dest)
			self.__logger.debug(f"Envoi d'une sonde de chemin vers {dest}.")
	
	### Méthodes pour la collecte des chemins empruntés par les sondes ###
	
	def recv_msg_cpu(self,packet: Packet):
		"""
		Reçoit et parse les messages sur le port CPU.
		Extrait la liste des routeurs traversés.
		Si on a pu extraire la liste, on l'ajoute dans la table des chemins reçus.

		:param packet: Paquet brut capturé.
		"""
		global PROTOCOL_PATH_TEST_RETURN
  
		try:
			hops		 = []
   
			# On vérifie que c'est un paquet Ethernet + IPv4
			if Ether in packet and IP in packet:
				ip	= packet[IP]

				# On s'assure que le protocole correspond à PROTOCOL_PATH_TEST_RETURN
				if ip.proto == PROTOCOL_PATH_TEST_RETURN:

					# On regarde si le paquet contient une en-tête custom_route
					if ProbeReturnHeader in packet:
						probe_header = packet[ProbeReturnHeader]
						
						# On parcourt les en-têtes custom_route
						for route in probe_header.custom_route:
							# Avec l'encapsulation, les adresses ip sont 
							# empilées dans l'ordre inverse de passage
							ip = str(IPv4Address(route.hop))
							hops.prepend(ip)

							if route.last_header == 1:
								break
			else:
				# Affiche le paquet reçu
				self.__logger.error("Paquet reçu non conforme.")
				self.__logger.error(f"Paquet reçu : {packet.summary()}")
				
			if len(hops) > 0:
				# On récupère l'adresse IP de la destination
				dest_ip = hops[-1]
				# On met à jour la table des chemins reçus
				self.__received_paths[dest_ip] = hops


		except Exception as e:
			self.__logger.error(f"Erreur lors du parsing du paquet : {e}")

	def sniff_cpu(self,start_sniffing:bool = True):
		"""
		Permet de sniffer les paquets sur le port CPU.
		"""
		# On vérifie si le sniffing est déjà en cours
		# Auquel cas, on ne fait rien
		if self.__sniff_running and start_sniffing:

			self.__logger.warning("Le sniffing est déjà en cours.")
			return
		# On vérifie si le sniffing est déjà arrêté
		# Auquel cas, on ne fait rien
		elif not self.__sniff_running and not start_sniffing:

			self.__logger.warning("Le sniffing est déjà arrêté.")
			return

		# Sinon, on va démarrer ou arrêter le sniffing
		else:
			# Si on veut démarrer le sniffing
			if start_sniffing:
				self.__logger.debug("Démarrage du sniffing...")
				# Définir le nombre de paquets à capturer maximum
				nb_packet_max 	= len(self.__routing_table)
				# On définit la fonction de callback pour le traitement des paquets
				rcv_packet		= lambda pkt : self.recv_msg_cpu(pkt)
				# On definit la fonction de stop
				stop_sniff		= lambda : not self.__sniff_running
				# On récupère l'interface CPU
				cpu_intf		= self.__topology.get_cpu_port_intf(self.__name)
				args			= {
									"iface":cpu_intf, 
									"prn":rcv_packet, 
									"stop_filter":stop_sniff, 
									"count":nb_packet_max
								}
				# On lance le sniffing dans un thread
				self.__sniff_thread = Thread(target=sniff,args=args)
				self.__sniff_thread.start()
				self.__sniff_running = True

			elif not start_sniffing:
				self.__logger.debug("Arrêt du sniffing...")
				# On arrête le sniffing
				self.__sniff_running = False
				self.__sniff_thread.join(timeout=3)
				self.__sniff_thread = None

	def get_cpu_interface(self):
		"""
		Récupère l'interface CPU du switch.
		"""
		return self.__topology.get_cpu_port_intf(self.__name)

	### Méthodes pour le diagnostic des anomalies ###
	
 
	def __diagnose_anomalies_links(self) -> list[int]:
		"""
		Diagnostique les anomalies sur les liens.
		return : list[int] | None : Liste des ports down, ou None si pas d'anomalie.
		"""
		# On récupère la liste des ports connectés en théorie au switch 
		ports = self.__topology.get_node_intfs(fields="port")[self.__name].copy()
		# On enlève le port CPU et le port de loopback
		ports.pop(self.__topology.get_cpu_port_intf(self.__name))
		ports.pop("lo")
		# On les convertit en entiers
		ports = [int(port) for port in ports.values()]

		# Met à jour les données links_up à partir du registre associé
		self.__links_up = self.read_register("links_up", None)
		# On liste les ports down (non présents dans la liste des liens up)
		ports_down = [ports_down for ports_down in ports if ports_down not in self.__links_up]

		if ports_down:
			self.__logger.warning(f"Anomalie détectée sur les ports {ports_down} : Liens down.")
		else:
			self.__logger.debug("Pas d'anomalie détectée sur les liens.")
		return ports_down

	def __diagnose_anomalies_paths(self) -> list | None:
		"""
		Diagnostique les anomalies sur les chemins.
		return : liste de pair contenant le chemins optimaux, et le chemin non optimal, rééllement emprunté.
		"""
		# On récupère les chemins non optimaux
		not_optimal_path	= list[tuple[list[str],list[str]]]()
		# Permet de stocker les correspondances entre les noms des switchs et les adresses IP
		match_ip_sw_names	= defaultdict[str]

		# On vient faire la correspondance entre les IP et les noms des switchs
		for sw in self.__topology.get_nodes():
			for intfs in self.__topology.get_interfaces(sw):
				match_ip_sw_names[intfs["ip"]] = sw

		# On parcourt  les chemins calculés
		for dest in self.__routing_table:
			# On ne s'intéresse pas aux hôtes, ou à soi-même
			# on ne peut encapsuler une sonde retour vers un hôte
			if self.__topology.isHost(dest) or dest == self.__name:
				continue
			# On récupère le chemin optimal
			optimal_path = self.__routing_table[dest]
			# On récupère le chemin reçu
			received_ip_path = []
			if dest in self.__received_paths:
				received_ip_path = self.__received_paths[dest]
			# On convertit les adresses IP en noms de switchs
			received_path = [match_ip_sw_names[ip] for ip in received_ip_path]
			# On compare les deux chemins
			if optimal_path != received_path:
				self.__logger.warning(f"Anomalie détectée sur le chemin vers {dest} : Chemin optimal {optimal_path}, chemin reçu {received_path}.")
				not_optimal_path.append((optimal_path,received_path))
		
		return not_optimal_path

	def diagnose_anomalies(self):
		"""
		Diagnostique les anomalies sur les liens et les chemins.
		"""
		stats = Stats()
  
		# On met à jour les statistiques du contrôleur à partir des registres
		self.__update_all_registers()
  
		# On diagnostique les anomalies à partir des statistiques
		stats.down_ports	= self.__diagnose_anomalies_links()
		stats.wrong_paths	= self.__diagnose_anomalies_paths()

		# On log les statistiques
		self.__logger.info("Rapport de détection d'anomalies : ")
		self.__logger.info(f"Nombre total de paquets perdus : {stats.total_packets_lost}")
		self.__logger.info(f"Nombre total de paquets sondes revenus / envoyés : {stats.total_probe_packets_returned} / {stats.total_probe_packets_sent}")
		if stats.down_ports:
			self.__logger.warning(f"Ports down : {stats.down_ports}")
		else:
			self.__logger.info("Tous les liens sont fonctionnels.")
		if stats.wrong_paths:
			for paths in stats.wrong_paths:
				self.__logger.warning(f"Chemin optimal : {paths[0]}, chemin réel : {paths[1]}")
		else:
			self.__logger.info("Pas de chemins non optimaux détectés.")
		
		return stats

	def get_statistics(self) -> Stats:
		"""
		Récupère les statistiques du contrôleur.
		__return: Stats : Statistiques du contrôleur.
		"""
		return Stats(
			total_packets_lost				= self.__total_packets_lost,
			total_probe_packets_sent		= self.__total_probe_packets_sent,
			total_probe_packets_returned	= self.__total_probe_packets_returned,
			down_ports						= self.__links_up,
			wrong_paths						= self.__received_paths
		)
