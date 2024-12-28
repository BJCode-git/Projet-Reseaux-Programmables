import os
import json

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from p4utils.mininetlib.network_API import NetworkAPI

from controllers.simple_router import SimpleRouter
from controllers.simple_router_loss import SimpleRouterLoss
from controllers.simple_router_stupid import SimpleRouterStupid

from time import sleep
from threading import Thread
from collections import defaultdict

from logging import getLogger, INFO, DEBUG, ERROR, WARNING, StreamHandler, Formatter

class MetaController:

	def __init__(self, topology_file:str):
		if not NetworkAPI().is_network_up():
			raise Exception("Le réseau n'est pas démarré.")
		if not os.path.exists(topology_file):
			raise FileNotFoundError("Le fichier de topologie n'existe pas.")
		
		self.__topology		= load_topo(topology_file)
		self.__controllers 	= {}
		self.__registers	= {}
		self.__running		= False
		self.__supervisor_T = None
	
		# Initialisation du logger
		self.__logger = getLogger("MetaController")
		self.__logger.setLevel(INFO)
		handler = StreamHandler()
		handler.setFormatter(Formatter("[%(levelname)s] %(name)s : %(message)s"))
		self.__logger.addHandler(handler)
  
		self.__init_controllers()	

	def __init_controllers(self):
		"""
		Initialise les contrôleurs et leurs registres pour chaque switch de la topologie.
		"""
		for p4switch in self.__topology.get_p4switches():
			
			# On regarde si le switch est un routeur simple à l'attribut "type"
			switch_type = p4switch.get("type", "simple_router")
			match switch_type:
				case "simple_router_loss":
					self.__controllers[p4switch]	= SimpleRouterLoss(p4switch, self.__topology)
				case "simple_router_stupid":
					self.__controllers[p4switch]	= SimpleRouterStupid(p4switch, self.__topology)
				case _:
					self.__controllers[p4switch]	= SimpleRouter(p4switch, self.__topology)

			self.__controllers[p4switch].run()			
			self.__registers[p4switch]		= self.__controllers[p4switch].get_register_arrays()

	def update_topology(self, topology_file:str):
		"""
		Met à jour la topologie du réseau.
		"""
		if not os.path.exists(topology_file):
			raise FileNotFoundError(f"Le fichier de topologie n'existe pas au chemin spécifié : {topology_file}")
		
		self.__topology = self.load_topology(topology_file)
		for _,controller in self.__controllers.items():
			controller.update_topology(self.topology)

	##### Méthode pour gérer les registres #####
	# Pas réellement utilisées ni adaptées, 
	# chaque contrôleur initie et gère ses registres lui-même
	
	def reset_all_registers(self):
		"""
		Réinitialise tous les registres de tous les contrôleurs.
		"""
		for controller in self.__controllers.values():
			controller.reset_registers()

	def read_register_on(self, switch_id:str, register_name:str):
		"""
		Lit la valeur d'un registre sur un switch.
		"""
		value = None
		try:
  
			value =self.__controllers[switch_id].read_register(register_name)
		
		except KeyError:
			self.__logger.error(f"Le switch {switch_id} n'existe pas.")
		except Exception as e:
			self.__logger.error(f"Erreur lors de la lecture du registre {register_name} sur le switch {switch_id} : {e}")

		finally:
			return value

	def write_register_on(self, switch_id:str, register_name:str, entry):
		"""
		Ecrit une valeur dans un registre sur un switch.
		"""
		try:
			self.__controllers[switch_id].write_register(register_name, entry)
		except KeyError:
			self.__logger.error(f"Le switch {switch_id} n'existe pas.")
		except Exception as e:
			self.__logger.error(f"Erreur lors de l'écriture du registre {register_name} sur le switch {switch_id} : {e}")

	def install_entry_on(self, switch_id:str, table_name:str, entry):
		"""
		Installe une entrée dans une table sur un switch.
		"""
		try:
			self.__controllers[switch_id].install_entry(table_name, entry)
		except KeyError:
			self.__logger.error(f"Le switch {switch_id} n'existe pas.")
		except Exception as e:
			self.__logger.error(f"Erreur lors de l'installation de l'entrée dans la table {table_name} sur le switch {switch_id} : {e}")

	def remove_entry_on(self, switch_id:str, table_name:str, entry):
		"""
		Supprime une entrée dans une table sur un switch.
		"""
		try:
			self.__controllers[switch_id].remove_entry(table_name, entry)
		except KeyError:
			self.__logger.error(f"Le switch {switch_id} n'existe pas.")
		except Exception as e:
			self.__logger.error(f"Erreur lors de la suppression de l'entrée dans la table {table_name} sur le switch {switch_id} : {e}")

	##### Méthode pour gérer la supervision #####

	def coordinate_probes(self):
		"""
		Demande à chaque contrôleur d'envoyer des sondes.
		"""
		for controller in self.__controllers.values():
			controller.send_probe_packets()

	def collect_all_statistics(self):
		"""
		Récupère les données de supervision pour chaque switch.
		"""
		stats = {}
		for switch_id, controller in self.__controllers.items():
			stats[switch_id] = controller.collect_link_statistics()
		return stats

	def diagnose_anomalies(self, threshold=0.1):
		"""
		Diagnostique les anomalies de pertes de paquets.
		"""
		stats = self.collect_all_statistics()
		for switch_id, data in stats.items():
			if data["loss_rate"] > threshold:
				self.__logger.warning(f"Anomalie détectée sur {switch_id} : Taux de perte {data['loss_rate']:.2%}")

	def get_linked_down(self):
		"""
		Récupère les liens qui sont down.
		"""
		linked_down = defaultdict(list)

		for switch_id, controller in self.__controllers.items():
			linked_down[switch_id] = controller.get_linked_down()
			for link in linked_down[switch_id]:
				self.__logger.warning(f"Le lien {link} est down sur le switch {switch_id}")

		return linked_down

	def supervise_network_links(self, measure_interval=10):
		"""
		Supervise les liens de tous les commutateurs dans le réseau.
		"""
  
		while self.__running:
			# On attend un certain temps avant de refaire une mesure
			sleep(measure_interval)

			# On ordonne à chaque contrôleur d'envoyer des sondes
			self.coordinate_probes()
			
			# On attend un peu pour que les sondes soient envoyées
			# Et que les statistiques soient collectées
			sleep(5)
   
			# On détecte les anomalies
			self.diagnose_anomalies()

			# On récupère les liens down
			self.get_linked_down()
   
			# On réinitialise les statistiques
			self.reset_all_registers()

	def run(self):
		"""
		Lance la supervision des liens du réseau.
		"""
		self.__running = True
		self.__supervisor_T = Thread(target=self.supervise_network_links)
		self.__supervisor_T.start()

	def stop(self):
		"""
		Arrête la supervision des liens du réseau.
		"""
		self.__running = False
		self.__supervisor_T.join(timeout=10)
		self.__supervisor_T = None