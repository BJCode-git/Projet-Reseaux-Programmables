import os
import json

import networkx as nx

from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from p4utils.mininetlib.network_API import NetworkAPI
from p4utils.utils.compiler import P4C
from p4utils.utils.helper import load_topo
from p4utils.utils.topology import Topology

from controllers.simple_router import SimpleRouter

from logging import getLogger, INFO, ERROR, WARNING, DEBUG, StreamHandler, Formatter

class SimpleRouterLoss(SimpleRouter):
	def __init__(self, 
			  	name: str, 
			   topology_file="topology.json", 
			   p4src="p4src/simple_router.p4", 
			   loss_rate=30, 
			   log_level=INFO):
		super().__init__(name, topology_file, p4src, log_level)
		
		# Taux de perte
		self.__loss_rate = loss_rate

		# Configuration du logger
		self.__logger.name = "SimpleRouterLoss"