#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

/** Définition des constantes **/
#define MAX_HOPS 				16
#define MAX_ROUTE_ENTRIES		216
#define MAX_PORTS_ENTRIES		16

/** Définition des ethernet types **/
#define ETHERTYPE_IPV4			0x0800
#define ETHERTYPE_CUSTOM 		0x8846

/** Définition de protocoles ipv4 personnalisés **/

/* Supervision des liens directs */

// Paquet déclencheur de tests de liens directs
#define PROTOCOL_LINK_TEST_TRIGGER	0x95
// Paquet aller de test de liens directs
#define PROTOCOL_LINK_TEST_SENT		0x96
// Paquet retour de test de liens directs
#define PROTOCOL_LINK_TEST_RETURN	0x97

/* Supervision des chemins */

// Paquet déclencheur de tests de routage
#define PROTOCOL_PATH_TEST_TRIGGER	0x98
// Paquet de sonde aller
#define PROTOCOL_PATH_TEST_SENT		0x99
// Paquet de sonde retour
#define PROTOCOL_PATH_TEST_RETURN 	0x9A


// Définition des types
typedef bit<4> 	Port_t;
typedef bit<16>	Counter_t;
typedef bit<9>	egressSpec_t;
typedef bit<48>	macAddr_t;
typedef bit<32>	ip4Addr_t;

// Déclaration des headers

/*
En-tête Ethernet
*/
header ethernet_t {
	macAddr_t	dstAddr;
	macAddr_t	srcAddr;
	bit<16>		etherType;
}

/*
Metadonnées pour ajouter des informations de routage
sur le paquet
*/
header custom_route_t {
	// Flag indiquant si c'est le dernier point de passage
	bit<8>		last_header;
	// Adresse IP à prendre pour le prochain saut
	ip4Addr_t	hop;
}

/*
En-tête de broadcast
*/
header broadcast_t {
	bit<8>	id;
	bit<8>	type;
}

/*
En-tête IPv4
*/
header ipv4_t {
	bit<4>		version;
	bit<4>		ihl;
	bit<8>		diffserv;
	bit<16>		totalLen;
	bit<16>		identification;
	bit<3>		flags;
	bit<13>		fragOffset;
	bit<8>		ttl;
	bit<8>		protocol;
	bit<16>		hdrChecksum;
	ip4Addr_t	srcAddr;
	ip4Addr_t	dstAddr;
}

struct metadata {
	/* Va contenir les informations du routeur (i.e. mac, ip) */
	//macAddr_t 	router_mac;
	ip4Addr_t 	route_origin_ip;
	ip4Addr_t 	router_ip;
	Port_t		cpu_port;
}

/*
En-tête d'un paquet
*/
struct headers {
	// En-tête Ethernets
	ethernet_t 					ethernet;
	// En-tête Personnalisé
	custom_route_t[MAX_HOPS]	custom_route;
	// En-tête de broadcast
	broadcast_t 				broadcast;
	// En-tête IPv4
	ipv4_t 						ipv4;
	// En-tête des données 
}



/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
				out headers hdr,
				inout metadata meta,
				inout standard_metadata_t standard_metadata) {

	state start {
		transition parse_ethernet;
	}

	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			// Si le type ethernet est un type IPv4,
			// on parse l'en-tête IPv4
			ETHERTYPE_IPV4: parse_ipv4;
			// Si le type ethernet est un type custom,
			// on parse l'en-tête custom_route
			ETHERTYPE_CUSTOM: parse_custom_route;
			// Sinon, on rejette le paquet
			default: reject;
		}
	}

	state parse_custom_route {
		// Extraction de l'en-tête custom_route
		packet.extract(hdr.custom_route);

		// On récupère l'ip du routeur d'origine du paquet pour la supervision des chemins
		meta.route_origin_ip = hdr.custom_route.hop;

		transition select(hdr.custom_route.last_header) {
			// Si c'est le dernier header, on parse l'en-tête IPv4
			1: parse_ipv4;
			// Sinon, on parse un autre header custom_route
			default: parse_custom_route;
		}
	}

	state parse_ipv4 {
		// Extraction de l'en-tête IPv4
		packet.extract(hdr.ipv4);
		// On accepte le paquet
		transition accept;
	}

}


/* 
	P4 Specification, clone de paquet ; 
	https://p4.org/p4-spec/docs/PSA.html#sec-contents-of-packets-sent-out-to-ports
	-> 6.8.1. Clone Examples

	Link monitor tutorial ;
	https://github.com/p4lang/tutorials/tree/master/exercises/link_monitor


	Multicast to all ports ;
	https://github.com/nsg-ethz/p4-learning/tree/master/examples/multicast
*/

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/


control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
	apply {
	}

}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control MyIngress(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata) {

	ip4Addr_t original_dstAddr;

	/***** Définition des registres *****/
	
		// On doit définir un registre pour stocker le port du CPU
		// Pour la supervision des chemins
		register<Port_t>(1) cpu_port;

		// On doit definir un registre loss_rate pour définir le taux de perte
		// des paquets pour le simple_router_loss
		register<bit<8>>(1)  loss_rate;

		// On doit definir un registre total_packets_lost pour compter le nombre
		// de paquets perdus / non routés.
		register<Counter_t>(1) total_packets_lost;

		// On définit un registre pour stocker le nombre de paquet sondes envoyés
		register<Counter_t>(1) total_probe_packets_sent;

		// On définit un registre pour stocker le nombre de paquet sondes revenus
		register<Counter_t>(1) total_probe_packets_returned;

		// On définit un registre qui contient la liste des ports actifs
		// Pour la supervision des liens directs avec les voisins
		register<Port_t>(MAX_PORTS_ENTRIES)	active_ports;
		register<Counter_t>(1) 				active_ports_size;

		// Pour la supervision des chemins, on encapsule les informations
		// Des routeurs lors du passage des paquets de sonde.
		// Au retour des paquets de sonde, on envoie le paquet au contrôleur
		// Pour qu'il puisse récupérer les informations de routage.
	
	/***** Définition des tables *****/

	// On doit définir une table de routage ipv4_lpm 
	// pour le routage classique et custom
	table ipv4_lpm {
		key = {
			ipv4.dstAddr: lpm;
		}
		actions {
			ipv4_forward;
			no_routing_action;
		}
		size : MAX_ROUTE_ENTRIES;
		default_action : no_routing_action;
	}

	// Table qui contient les informations sur le routeur
	// Pour la supervision des liens directs avec les voisins
	// Il s'agit des infos que le routeur envoie à ses voisins
	// Dans les paquets de sonde
	table router_info {
		key = {
			ipv4.dstAddr: exact;
		}
		actions {
			route_back_path_probe;
			NoAction;
		}
		default_action : NoAction;
		size : 1;
	}


	/***** Définition des actions *****/

	/* Configuration du routeur */
	action route_back_path_probe() {
		// On transforme le type du paquet en paquet de sonde retour
		hdr.ipv4.protocol = PROTOCOL_PATH_TEST_RETURN;
		// Renvoyer le paquet à la source
		hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
	}

	action set_cpu_info() {
		meta.cpu_port = cpu_port.read(0);
	}

	/** Actions pour le routage **/

	// On définit une action par défaut qui va dropper les paquets
	// à minima et qui pourra introduire des mesures de monitoring

	action no_routing_action() {
		// On incrémente le nombre de paquets perdus
		// dans le registre total_packets_lost
		bit<32> tmp;
		tmp = total_packets_lost.read(0);
		total_packets_lost.write(0, tmp + 1);

		// On marque le paquet à dropper
		mark_to_drop(standard_metadata);
	}

	// On définit l'action pour le routage classique ipv4_forward
	// qui va router le paquet sur le port de sortie
	//met à jour les adresses MAC et IP de provenance et de destination du paquet
	action ipv4_forward(egressSpec_t port, macAddr_t dstAddr, ip4Addr_t ip_out) {

		// On décrémente le TTL
		header.ipv4.ttl 		= header.ipv4.ttl - 1;

		// On définit l'adresse MAC source du paquet
		// Comme celle du routeur actuel
		header.ethernet.srcAddr = hdr.ethernet.dstAddr;

		// On définit l'adresse MAC de destination
		// Fournie par la table de routage
		header.ethernet.dstAddr = dstAddr;

		// On définit le port de sortie
		// Egalement fourni par la table de routage
		standard_metadata.egress_spec = port;

		// Définit l'ip de l'interface de sortie du paquet
		meta.router_ip = ip_out;
	}

	// On définit l'action pour le broadcast des paquets de sonde sur tous les ports
	action broadcast(){
		standard_metadata.mcast_grp = 1;
		hdr.broadcast.setValid();
		hdr.broadcast.id			= 1;
		hdr.broadcast.type			= 0X10;
	}

	/** Actions sur les registres **/

	// Action qui prend en paramètre un port et qui sauvegarde ce port
	// dans le registre des ports actifs
	action save_active_port(bit<16> port) {

		// On récupère l'index où sauvegarder le port
		bit<9> size;
		size = active_ports_size.read(0);
		
		// on sauvegarde le port dans le registre des ports actifs
		active_ports.write(size, port);
		// on incrémente la taille du registre
		active_ports_size.write(0, size + 1);
	}

	// Action pour incrémenter le nombre de paquets perdus
	action increment_packets_lost() {
		bit<32> tmp;
		tmp = total_packets_lost.read(0);
		total_packets_lost.write(0, tmp + 1);
	}

	// Action pour incrémenter le nombre de paquets de sonde retournés
	action increment_probe_packets_returned() {
		bit<32> tmp;
		tmp = total_probe_packets_returned.read(0);
		total_probe_packets_returned.write(0, tmp + 1);
	}

	// Action pour incrémenter le nombre de paquets de sonde envoyés
	action increment_probe_packets_sent() {
		bit<32> tmp;
		tmp = total_probe_packets_sent.read(0);
		total_probe_packets_sent.write(0, tmp + 1);
	}


/***** Application des règles *****/

	apply{

		// On récupère l'adresse MAC et l'adresse IP du routeur
		// Pour la supervision des liens directs avec les voisins
		set_cpu_info();

		// on regarde si le paquet est un paquet de sonde
		if(	hdr.ipv4.isValid() && 
			(	PROTOCOL_LINK_TEST_TRIGGER < = hdr.ipv4.protocol  	&& 
				hdr.ipv4.protocol < = PROTOCOL_PATH_TEST_RETURN
			)
		  )
		{

			select (hdr.ip4.protocol){

				/***** Supervision des liens directs *****/

				// Si on reçoit un paquet sonde déclencheur de test de liens directs
				PROTOCOL_LINK_TEST_TRIGGER : 

					// On transforme le type du paquet en paquet de sonde aller
					hdr.ipv4.protocol = PROTOCOL_LINK_TEST_SENT;
					// On envoie un paquet de sonde aller
					// Sur tous les ports
					broadcast();
					// On incrémente le nombre de paquets de sonde envoyés
					increment_probe_packets_sent();

				// Si on reçoit un paquet sonde retour de test de liens directs
				PROTOCOL_LINK_TEST_SENT :

					// On transforme le type du paquet en paquet de sonde retour
					hdr.ipv4.protocol = PROTOCOL_LINK_TEST_RETURN;

					// On renvoie le paquet à la source (sur le port d'origine)
					ipv4_forward(hdr.ethernet.srcAddr, standard_metadata.ingress_port);

					// On clone le paquet pour le router sur les autres ports
					clone_egress_packet_to_port(standard_metadata.ingress_port);

				// Si on reçoit un paquet sonde retour de test de liens directs
				PROTOCOL_LINK_TEST_RETURN :

					// On sauvegarde le port d'entrée
					// Pour la supervision des liens directs avec les voisins
					save_active_port(standard_metadata.ingress_port);
	
					// On incrémente le nombre de paquets de sonde retournés
					increment_probe_packets_returned();

				/***** Supervision des chemins *****/

				// Si on reçoit un paquet sonde déclencheur de test de routage
				PROTOCOL_PATH_TEST_TRIGGER :

					// On transforme le type du paquet en paquet de sonde aller
					hdr.ipv4.protocol = PROTOCOL_PATH_TEST_SENT;

					// On route le paquet 
					ipv4_lpm.apply();

					// On push l'adresse ip du routeur de départ
					// Pour indiquer le passage par le routeur
					hdr.custom_route.push_front(1);
					hdr.custom_route[0].last_header = 1;
					hdr.custom_route[0].hop = meta.router_ip;
					hdr.custom_route[0].setValid();
					

					// On incrémente le nombre de paquets de sonde envoyés
					increment_probe_packets_sent();
				
				// Si on reçoit un paquet sonde de routage aller
				PROTOCOL_PATH_TEST_SENT :

					// On regarde si l'adresse de destination est celle du routeur
					// On regarde ça dans la table router_info

					// On regarde si le paquet est destiné au routeur
					router_info.apply();

					// Routage du paquet
					ipv4_lpm.apply();

					// On push l'adresse ip du routeur actuel
					// Pour indiquer le passage par le routeur
					hdr.custom_route.push_front(1);
					hdr.custom_route[0].last_header = 0;
					hdr.custom_route[0].hop 		= meta.router_ip;
					hdr.custom_route[0].setValid();

				
				// Si on reçoit un paquet sonde de chemin retour
				PROTOCOL_PATH_TEST_RETURN :

					
					// On regarde si le paquet nous est destiné
					// i.e, le paquet arrive sur notre adresse IP source
					// En regardant s'il y a un hit dans la table router_info
					if( router_info.apply().hit ) {

						// Si le paquet est destiné au routeur
						// On renvoie le paquet au contrôleur via le port CPU
						standard_metadata.egress_spec = meta.cpu_port;

						// On incrémente le nombre de paquets de sonde retournés
						increment_probe_packets_returned();
					}

					// Sinon, on route le paquet vers sa destination
					else {
						ipv4_lpm.apply();
					}

			}

		}

		// Si le paquet n'est pas un paquet de sonde
		else{

			// on tire un nombre aléatoire entre 0 et 100
			// pour simuler le taux de perte des paquets
			// de simple_router_loss. 
			// Pour simple_router et simple_router_stupid, 
			// le taux de perte est de 0.
			bit<32> random_value;
			modify_field_rng_uniform(random_value, 0, 99);

			// Si le nombre aléatoire est inférieur au taux de perte
			// on drop le paquet (simulation de perte -> simple_router_loss)
			if (random_value < loss_rate) {
				no_routing_action();
			}
			
			// Sinon, on route le paquet normalement
			else{
				
				// On sauvegarde l'adresse de destination ipv4 initiale
				// Pour la restaurer après le routage personnalisé
				original_dstAddr = hdr.ipv4.dstAddr;

				// On regarde si on a un paquet ipv4 valide
				if (hdr.ipv4.isValid()) {
					
					// On regarde si on a un paquet custom
					// Et s'il reste des points de passage à traverser
					if (hdr.custom_route[0].isValid()) {
						// Mettre à jour l'adresse de destination avec le prochain saut
						hdr.ipv4.dstAddr = hdr.custom_route[0].hop;
					}

					// On applique le routage si le TTL est supérieur à 0
					if(hdr.ipv4.ttl > 0) {
						ipv4_lpm.apply();
					}
					else {
						no_routing_action();
					}

					// Si on a un paquet custom et qu'on a modifié l'adresse de destination
					// On a obtenu le port de sortie, on peut donc router le paquet
					// On remet maintenant l'adresse de destination initiale
					// Ceci permet de router le paquet correctement après avoir 
					// Emprunter le chemin personnalisé
					if (hdr.custom_route[0].isValid()) {
						hdr.ipv4.dstAddr = original_dstAddr;

						// Si c'est le dernier point de passage,
						// On remet le ethernet type à ETHERTYPE_IPV4
						if (hdr.custom_route[0].last_header == 1) {
							hdr.ethernet.etherType = ETHERTYPE_IPV4;
						}

						// On pop l'en-tête avec le point de passage actuel
						hdr.source_routes.pop_front(1);
					}

				}
			}

		}

	}

}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
				 inout metadata meta,
				 inout standard_metadata_t standard_metadata) {

	apply {
	}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
	apply {
	}
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
	apply {
		packet.emit(hdr.ethernet);
		packet.emit(hdr.custom_route);
		packet.emit(hdr.broadcast);
		packet.emit(hdr.ipv4);
	}
}


// Configuration du pipeline complet
V1Switch(
			MyParser(),
			MyVerifyChecksum(),
			MyIngress(), 
			MyEgress(),
			MyComputeChecksum(),
			MyDeparser()
) main;