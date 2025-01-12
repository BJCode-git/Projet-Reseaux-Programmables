import os
from time import sleep
from threading import Thread

from collections import defaultdict
from typing import Callable

from scapy.all import Packet, sniff

from p4utils.utils.helper import load_topo
from p4utils.utils.topology import NetworkGraph # , Topology

# Import des contrôleurs
from simple_router import SimpleRouter
from simple_router_loss import SimpleRouterLoss
from simple_router_stupid import SimpleRouterStupid
#Import de la structure pour les statistiques
from simple_router import Stats




from logging import getLogger, INFO, StreamHandler, Formatter

class MetaController:
	"""
	Contrôleur principal qui gère les contrôleurs de chaque switch.
	"""

	def __init__(self, topology_file:str):
		if not os.path.exists(topology_file):
			raise FileNotFoundError("Le fichier de topologie n'existe pas.")

		self.__topology		: NetworkGraph	= load_topo(topology_file)
		self.__controllers					= defaultdict(SimpleRouter)
		self.__registers					= defaultdict(dict)
		self.__running 		: bool			= False
		self.__supervisor_T : Thread		= Thread(target=self.__supervise_network_thread)
		self.__running_sniff				= None
		self.__sniffing_T					= None

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
		types  = self.__topology.get_p4switches(fields="type")
		for p4switch in self.__topology.get_p4switches():

			# On regarde si le switch est un routeur simple à l'attribut "type"
			switch_type = types[p4switch]
			match switch_type:
				case "simple_router_loss":
					self.__controllers[p4switch]	= SimpleRouterLoss(p4switch, self.__topology)
				case "simple_router_stupid":
					self.__controllers[p4switch]	= SimpleRouterStupid(p4switch, self.__topology)
				case _:
					self.__controllers[p4switch]	= SimpleRouter(p4switch, self.__topology)

			self.__registers[p4switch]		= self.__controllers[p4switch].get_register_arrays()

	def update_topology(self, topology_file:str):
		"""
		Met à jour la topologie du réseau.
		"""
		if not os.path.exists(topology_file):
			raise FileNotFoundError(f"Le fichier de topologie n'existe pas au chemin spécifié : {topology_file}")

		self.__topology = load_topo(topology_file)
		for _,controller in self.__controllers.items():
			controller.update_topology(self.__topology)

	##### Méthode pour gérer les registres #####
	# Pas réellement utilisées ni adaptées,
	# chaque contrôleur initie et gère ses registres lui-même

	def __reset_all_registers(self):
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

	def __sniff_on_cpu_ports(self):
		"""
		Lance le sniffing sur les ports cpu des switchs.
		"""
		if self.__running_sniff:
			self.__logger.warning("Le sniffing est déjà en cours.")
			return
		else:
			match_sw_cpu_intf = dict(str)
			for sw in self.__controllers:
				match_sw_cpu_intf[sw] = self.__topology.get_cpu_port_intf(sw)

			pkt_callback : Callable[[Packet],None] = lambda pkt: self.__controllers[match_sw_cpu_intf[pkt.sniffed_on]].process_packet(pkt)

			stop_condition = lambda: not self.__running_sniff
			max_packets = len(self.__controllers) * len(self.__controllers)

			args = {
				"iface"		:	match_sw_cpu_intf.values(),
				"prn"		:	pkt_callback,
				"stop_filter":	stop_condition,
				"count"		:	max_packets

			}
			self.__sniffing_T = Thread(target=sniff, args=args)
			self.__sniffing_T.start()
			self.__running_sniff = True

	def __stop_sniffing_on_cpu_ports(self):
		"""
		Arrête le sniffing sur les ports cpu des switchs.
		"""
		if self.__running_sniff:
			self.__running_sniff = False
			self.__sniffing_T.join(timeout=5)
			self.__sniffing_T = None
		else:
			self.__logger.warning("_stop_sniffing : Le sniffing n'est pas en cours.")

	def __coordinate_probes(self):
		"""
		Demande à chaque contrôleur d'envoyer des sondes.
		"""
		for controller in self.__controllers.values():
			controller.send_probe_packets()

	def __collect_all_statistics(self):
		"""
		Récupère les données de supervision pour chaque switch.
		"""
		stats = defaultdict(Stats)
		for switch_id, controller in self.__controllers.items():
			stats[switch_id] = controller.get_statistics()
		return stats

	def __diagnose_anomalies(self):
		"""
		Diagnostique les anomalies de pertes de paquets.
		Chaque contrôleur doit avoir une méthode diagnose_anomalies.
		Les contrôleurs procèdent individuellement à la détection de leurs propres anomalies.
		"""
		for controller in self.__controllers.values():
			controller.diagnose_anomalies()

	def __react_to_anomalies(self):
		"""
		Réagit aux anomalies détectées.
		"""
		# On récupère les statistiques
		stats = self.__collect_all_statistics()

		# 2 phases pour réagir aux anomalies
		# 1ere phase :
		# 	Pour chaque port qui ne marche pas, on identifie le lien associé,
		# 	Et on le supprime de la topologie, ou on affecte un poids infini.
		# 2eme phase :
		# 	Pour chaque lien emprunté à la place d'un autre dans le chemin optimal,
		# 	On augmente le poids du lien emprunté de 1.

		# On copie la topologie pour la modifier
		topology = self.__topology.copy()

		# On récupère la liste des hôtes connectés aux interfaces des switchs
		# Pour pouvoir identifier les liens
		intfs = topology.get_intfs(fields="port")

		# On parcourt les statistiques pour chaque switch
		for switch_id in stats:

			### 1ere phase ###
			# Pour chaque port qui ne marche pas, on supprime le lien associé
			for port in stats[switch_id].down_ports:
				# On identifie le voisin associé au port
				neighbour = None
				for n, p in intfs.items():
					if p == port:
						neighbour = n
						break
				# On supprime le lien de la topologie
				if neighbour is not None:
					topology.remove_link(switch_id, neighbour)
					self.__logger.info(f"Le lien entre {switch_id} et {neighbour} a été supprimé de la topologie.")

			### 2eme phase ###
			# Pour chaque chemin emprunté à la place d'un autre dans le chemin optimal
			for paths in stats[switch_id].wrong_paths :
				optimal_path	= paths[0]
				wrong_path		= paths[1]
				min_size = min(len(optimal_path), len(wrong_path))

				# On regarde si les chemins sont différents
				# Si c'est le cas, on augmente le poids des liens empruntés
				for i in range(min_size):
					if optimal_path[i] != wrong_path[i]:
						# On récupère le poids du lien emprunté, ou 1 si le lien n'existe pas
						weight = topology.get_edge_data(switch_id, wrong_path[i],{"weight":1})["weight"]
						# On augmente le poids du lien emprunté de 1
						weight += 1
						# Si le lien n'existe pas, il est ajouté, sinon met à jour le poids
						topology.add_edge(switch_id, wrong_path[i], weight=weight)

				# On regarde si le chemin emprunté est plus long que le chemin optimal
				# Si c'est le cas, on augmente le poids des liens empruntés
				for i in range(min_size,len(wrong_path)):
					weight = topology.get_edge_data(switch_id, wrong_path[i],{"weight":1})["weight"]
					weight += 1
					topology.add_edge(switch_id, wrong_path[i], weight=weight)

	def __supervise_network_thread(self, measure_interval=10):
		"""
		Supervise les liens de tous les commutateurs dans le réseau.
		"""

		while self.__running:
			# On attend un certain temps avant de refaire une mesure
			sleep(measure_interval)

			# On réinitialise les registres des routeurs
			# Et donc les statistiques associées
			self.__reset_all_registers()

			# On va ordonner à chaque contrôleur d'envoyer des sondes,
			# Au préalable, on va lancer le sniffing sur les ports cpu
			# Pour récupérer les chemins empruntés

			# On lance le sniffing sur les ports cpu
			# 2 facçons de faire :
			# - Soit on ordonne à chaque contrôleur de lancer le sniffing
			#		(chaque contrôleur a une méthode et démarre un nouveau thread)
			# - Soit on le fait ici, et on commute les paquets vers le bon contrôleur
			# On va choisir la 2eme option

			self.__sniff_on_cpu_ports()

			# On envoie donc les sondes
			self.__coordinate_probes()

			# On attend un peu pour que les sondes soient envoyées
			# Et que les statistiques soient collectées
			sleep(5)

			self.__stop_sniffing_on_cpu_ports()

			# On détecte les anomalies
			self.__diagnose_anomalies()

			# Eventuellement, on réagit aux anomalies
			#self.__react_to_anomalies()


	def start_supervising(self):
		"""
		Lance la supervision des liens du réseau.
		"""
		self.__running = True
		if self.__supervisor_T is None:
			self.__supervisor_T = Thread(target=self.__supervise_network_thread)
		self.__supervisor_T.start()

	def stop_supervising(self):
		"""
		Arrête la supervision des liens du réseau.
		"""
		self.__running = False
		# On arrête le sniffing au besoin
		self.__stop_sniffing_on_cpu_ports()
		self.__supervisor_T.join(timeout=10)
		self.__supervisor_T = None



if __name__ == "__main__":
	mc = MetaController("topology.json")
	mc.start_supervising()
	sleep(120)
	mc.stop_supervising()