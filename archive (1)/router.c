#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "protocols.h"
#include "queue.h"
#include "lib.h"


struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *mac_table;
int mac_table_len;
// cu ajutorul unei cautari binare, reusesc sa gasesc rapid intrarea - O(log(n))
struct route_table_entry *get_best_route(uint32_t ip_dest, int st, int dr) {
	struct route_table_entry *best = NULL;
	int mid = (st + dr) / 2;
	if (st > dr) {
		return best;
	}
	// daca ne-a mai ramas un singur element verificam daca IP-ul destinatie mascat e acelasi cu prefixul din intrare mascat
	if (st == dr) {
		if (ntohl(rtable[mid].prefix & rtable[mid].mask) == ntohl(ip_dest & rtable[mid].mask)) {
			return &rtable[mid];
		}
		return best;
	}
	// daca gasesc un prefix potrivit, verific inainte si inapoi pentru valoarea cea mai restrictiva a mastii (cea mai mare)
	if (ntohl(rtable[mid].prefix & rtable[mid].mask) == ntohl(ip_dest & rtable[mid].mask)) {
		best = &rtable[mid];
		int aux_mid = mid;
		// mergem inapoi in tabela, iar daca valoarea convertita a mastii e mai mare decat cea actuala(best) vom modifica best
		// ne asiguram ca nu iesim din tabela si ca prefixul mascat este inca egal cu destinatia mascata 
		while ((aux_mid >= 0) && ((rtable[aux_mid].prefix & rtable[aux_mid].mask) == (ip_dest & rtable[aux_mid].mask))) {
			if (ntohl(best->mask) < ntohl(rtable[aux_mid].mask)) {
				//noua atribuire
				best = &rtable[aux_mid];
			}
			aux_mid--;
		}
		// facem verificarea si inainte cu aceleasi specificatii
		while ((mid < rtable_len) && ((rtable[mid].prefix & rtable[mid].mask) == (ip_dest & rtable[mid].mask))) {
			
			if (ntohl(best->mask) < ntohl(rtable[mid].mask)) {
				best = &rtable[mid];
			}
			mid++;
		}
		//in final returnam pointerul catre intrarea respectiva
		return best;
		// daca prefixul mascat are valoare mai mare inseamna ca trebuie sa ne mutam in jumatatea de jos
	} else if (ntohl(rtable[mid].prefix & rtable[mid].mask) > ntohl(ip_dest & rtable[mid].mask)) {
		return get_best_route(ip_dest, st, mid - 1);
	} else {
		// altfel ne mutam in jumatatea de sus a tabelei
		return get_best_route(ip_dest, mid + 1, dr);
	}
}
// parcurgem tabela ARP si comparam IP-ul dat dupa ce gasim o intrare in tabela de rutare (best->next_hop) cu IP-urile din tabela ARP 
// gasim adresa MAC pentru acel router
struct arp_table_entry *get_mac_entry(uint32_t given_ip) {
	
	for (int i = 0; i < mac_table_len; i++)
		if (mac_table[i].ip == given_ip)
			return &mac_table[i];
	return NULL;
}
// functia de comparare pentru quicksort
// luam 2 valori rezultate de aplicarea mastii peste prefix, ordonand crescator
int compare_prefix(const void *a, const void *b) {
	//am ales sa convertesc in host_byte_order si sa mentin si in cautarea binara
	uint32_t aa = ntohl(((struct route_table_entry*)a)->prefix & ((struct route_table_entry*)a)->mask);
	uint32_t bb = ntohl(((struct route_table_entry*)b)->prefix & ((struct route_table_entry*)b)->mask);
	if (aa < bb)
		return -1;
	if (aa > bb) 
		return 1;
	return 0;
}
// sortarea tabelei de rutare
void sort_rtable() {
    qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_prefix);
}
// aceasta functie este folosita pentru crearea si trimiterea unui pachet raspuns cu protocolul ICMP
// avem 3 situatii acoperite, daca timpul de traire a pachetului s-a sfarsit, daca nu gasim in tabela de rutare IP-ul destinatie
// sau daca trimitem un raspuns ICMP "Echo reply" dupa ce am primit un pachet ICMP "Echo request" 
// pachetele trebuie sa ajunga inapoi la sursa
void icmp(struct ip_hdr *ip_hdr, char *buf, size_t interface, struct ether_hdr *eth_hdr, int type, int len) {
	// cream noul buffer
	char new_buf[MAX_PACKET_LEN];
	struct ether_hdr *new_eth_hdr = (struct ether_hdr *) new_buf;
	// in noul ethernet header vom seta adresa MAC de destinatie ca adresa MAC a sursei de la pachetul vechi
	memcpy(new_eth_hdr->ethr_dhost, eth_hdr->ethr_shost, sizeof(new_eth_hdr->ethr_dhost));
	// afirmam ca e protocol IPv4
	new_eth_hdr->ethr_type = ntohs(0x0800);
	// setam noul IP header
	struct ip_hdr *new_ip_hdr = (struct ip_hdr *)(new_buf + sizeof(struct ether_hdr));
	new_ip_hdr->ver = 4;
	new_ip_hdr->ihl = 5;
	new_ip_hdr->tos = 0;
	if (type != 0)
		// lungimea e definita de marimea lui, a ICMP-ului si urmatorii 8 bytes 
		new_ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
	else {
		// facem rost de toate datele in situatia in care vom avea tip "Echo reply"
		int len_echo = len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr) - sizeof(struct icmp_hdr);
		new_ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + len_echo);	
	}
	new_ip_hdr->id = 4;
	new_ip_hdr->frag = 0;
	new_ip_hdr->ttl = 255;
	// sa se stie ca e protocol ICMP
	new_ip_hdr->proto = IPPROTO_ICMP; 
	// facem rost de adresa IP a sursei
	new_ip_hdr->source_addr = inet_addr(get_interface_ip(interface));
	// setam adresa IP de destinatie cu aresa IP sursa a pachetului vechi
	new_ip_hdr->dest_addr = ip_hdr->source_addr;
	new_ip_hdr->checksum = 0;
	// calculam checksum
	new_ip_hdr->checksum = htons(checksum((uint16_t *)new_ip_hdr, sizeof(struct ip_hdr)));
	struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(new_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
	// setam tipul pachetului
	icmp_hdr->mtype = type;
 	icmp_hdr->mcode = 0;
	icmp_hdr->check = 0;
	icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmp_hdr)));
	if (type == 0) {
		// copiem ce se afla in IP header-ul vechi si continutul de dupa el in cazul "Echo reply"
		int len_echo = len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr) - sizeof(struct icmp_hdr);
		memcpy((char *)new_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), ip_hdr, sizeof(struct ip_hdr) + len_echo);
		send_to_link(len, new_buf, interface);
	} else {
		// copiem ce se afla in IP header-ul vechi si doar 8 bytes din continutul de dupa el
		memcpy((char *)new_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), ip_hdr, sizeof(struct ip_hdr) + 8);
		size_t length = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;
		// il trimitem mai departe folosindu-ne de functia din API
		send_to_link(length, new_buf, interface);
	}
 }
 
int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);
	rtable = malloc(sizeof(struct route_table_entry) * 70000);
	mac_table = malloc(sizeof(struct  arp_table_entry) * 10);
	//preluam tabela de rutare
	rtable_len = read_rtable(argv[1], rtable);
	// o ordonam 
	sort_rtable();
	// preluam tabela ARP
	mac_table_len = parse_arp_table("arp_table.txt", mac_table);
	
	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		// setam pointerul la inceputul bufferului
		struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
		// setam dupa structura headerului ethernet
		struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
		//verificam daca e protocol IPv4
		if (eth_hdr->ethr_type != ntohs(0x0800)) {
			// daca nu e, ignoram pachetul
			continue;
		}
		// verificam daca continutul pachetului a fost corupt
		if (checksum((uint16_t *) ip_hdr, sizeof(struct ip_hdr)) != 0)
			continue;
		// verificam daca pachetul primit e de tip ICMP si daca destinatia e chiar IP-ul routerului nostru
		if (ip_hdr->proto == IPPROTO_ICMP && ip_hdr->dest_addr == inet_addr(get_interface_ip(interface))) {
			struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
			if (icmp_hdr->mtype == 8) {
				//generam si trimitem pachetul de raspuns
				icmp(ip_hdr, buf, interface, eth_hdr, 0, len);
				continue;
			}
		}
		// cautam urmatoarea intrare
		struct route_table_entry *best = get_best_route(ip_hdr->dest_addr, 0, rtable_len);
		// daca nu o gasim, trimitem un pachet inapoi catre sursa pentru a o anunta
		if (best == NULL) {
			icmp(ip_hdr, buf, interface, eth_hdr, 3, len);
			continue;
		}
		// daca timpul de traire se scurge vom anunta
		if (ip_hdr->ttl <= 1) {
			icmp(ip_hdr, buf, interface, eth_hdr, 11, len);
			continue;
		}
		ip_hdr->ttl--;
		ip_hdr->checksum = 0;
		// recalculam checksum
		ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));
		// facem rost de adresa MAC pentru urmatoarea interfata
		struct arp_table_entry *mac_address = get_mac_entry(best->next_hop);
		if (mac_address == NULL)
			continue;
		// modificam adresa MAC destinatie pentru header-ul ethernet
		memcpy(eth_hdr->ethr_dhost, mac_address->mac, sizeof(eth_hdr->ethr_dhost));
		// modificam adresa MAC sursa pentru header-ul ethernet
		get_interface_mac(best->interface, eth_hdr->ethr_shost);
		// trimitem pachetul catre urmatorul router
		send_to_link(len, buf, best->interface);

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
	}
}

