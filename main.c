#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_dev.h>
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <sys/stat.h>

#include "rte_ethdev_gso.h"

#define TEST_UFO 1

#define CKSUM_OFFLOAD 0

/* unchanged macros */
#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

/* mbuf number per mempool */
#define NMBUF_PER_MEMPOOL (TX_RING_SIZE * 1 * 64)

#ifdef TEST_UFO
	/* always change macros */
	#define L4_PAYLOAD_LEN (1000-8)
	#define L4_LEN (8+L4_PAYLOAD_LEN)
	#define L3_LEN (20+L4_LEN)
	#define HEADER_LENGTH 42//14+20+8
	#define L2_LEN (HEADER_LENGTH+L4_PAYLOAD_LEN)
#elif TEST_TCP
	#define L4_PAYLOAD_LEN 1500
	#define L4_LEN (20+L4_PAYLOAD_LEN)
	#define L3_LEN (20+L4_LEN)
	#define HEADER_LENGTH 54//14+20+20
	#define L2_LEN (HEADER_LENGTH+L4_PAYLOAD_LEN)
#endif

/* GSO-related macros */
#ifdef TEST_UFO
	#define MSS ((L4_LEN/10)+14+20)
#elif TEST_TCP
	#define MSS ((L4_PAYLOAD_LEN/10)+14+20+20 )
#endif

/* mbuf size in a mempool */
#ifdef TEST_NORMAL_PACKET
	#define MBUF_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#else
	#define MBUF_SIZE (2*L2_LEN)
#endif

/*one mempool for TXRX, another for GSO */
#define MEMPOOL_NUM 2
#define TXRX 0
#define GSO 1
static struct rte_mempool *mempools[2];
static char *mempool_names[2];

static unsigned nb_ports;

/* GSO related parameters */
#define MAX_GSO_OUT_SEGMENT_NB 1000
//static uint16_t tx_pkts_sz = MAX_GSO_OUT_SEGMENT_NB;
//static struct rte_mbuf *tx_packets[MAX_GSO_OUT_SEGMENT_NB];
static struct rte_mbuf *tx_packet0;	//the normal mbuf.

struct _statistic_ {
	uint64_t tx_pkts;
	uint64_t rx_pkts;
};

static struct _statistic_ statistic = {
	.tx_pkts = 0,
	.rx_pkts = 0
};

/*
 *  * Ethernet device configuration.
 *   */
static struct rte_eth_rxmode rx_mode = {
	//.max_rx_pkt_len = ETHER_MAX_LEN, /**< Default maximum frame length. */
	//.max_rx_pkt_len = 0x2600, 
	//.max_rx_pkt_len = L2_LEN*2, 
	.split_hdr_size = 0, 
	.header_split   = 0, /**< Header Split disabled. */
	.hw_ip_checksum = 0, /**< IP checksum offload disabled. */
	.hw_vlan_filter = 0, /**< VLAN filtering enabled. */
	.hw_vlan_strip  = 0, /**< VLAN strip enabled. */
	.hw_vlan_extend = 0, /**< Extended VLAN disabled. */
	.jumbo_frame    = 0, /**< Jumbo Frame Support disabled. */
	.hw_strip_crc   = 0, /**< CRC stripping by hardware disabled. */
};

static struct rte_eth_txmode tx_mode = {
	.mq_mode = ETH_MQ_TX_NONE
};

static struct rte_eth_conf port_conf_default;
static void
packet_ipv4hdr_constructor(struct ipv4_hdr *iph)
{
	iph->version_ihl = 0x40 | 0x05;
	iph->type_of_service = 0;
	iph->packet_id = 0;
	/* fragment_offset shouldn't be 0! */
	iph->fragment_offset = htons(IPV4_HDR_DF_MASK);
	iph->time_to_live = 64;

	/* Total length of L3 */
	iph->total_length = htons(L3_LEN);

	iph->next_proto_id = IPPROTO_UDP;
	iph->src_addr = inet_addr("1.1.1.3");
	iph->dst_addr = inet_addr("1.1.2.3");
}

#ifdef PRINT_INFO
static
void display_mac_address(struct ether_hdr *ethh, uint8_t pid_from, uint8_t pid_to)
{
	printf("port_from %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)pid_from,
			ethh->s_addr.addr_bytes[0], ethh->s_addr.addr_bytes[1],
			ethh->s_addr.addr_bytes[2], ethh->s_addr.addr_bytes[3],
			ethh->s_addr.addr_bytes[4], ethh->s_addr.addr_bytes[5]);
	printf("port_to %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)pid_to,
			ethh->d_addr.addr_bytes[0], ethh->d_addr.addr_bytes[1],
			ethh->d_addr.addr_bytes[2], ethh->d_addr.addr_bytes[3],
			ethh->d_addr.addr_bytes[4], ethh->d_addr.addr_bytes[5]);
}
#endif

static void
packet_constructor_udp(char *pkt, uint8_t pid_from, uint16_t payload_len)
{
	struct ether_hdr *ethh;
	struct ipv4_hdr *iph;
	struct udp_hdr *udph;
	char *data;

	ethh = (struct ether_hdr *)pkt;
	iph = (struct ipv4_hdr *)((unsigned char *)ethh + sizeof(struct ether_hdr));
	udph = (struct udp_hdr *)((char *)iph + sizeof(struct ipv4_hdr));

	//1. fill in payload for the packet
	data = ((char *)udph + sizeof(struct udp_hdr));
	for(int i = 0; i < payload_len; i++) {
		*(data + i) = '1';
	}
	//2. fill in headers for the packet
	ethh->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	rte_eth_macaddr_get(pid_from, &(ethh->s_addr));
	
	//3c:fd:fe:9d:23:35
	ethh->d_addr.addr_bytes[0] = 0x3c;
	ethh->d_addr.addr_bytes[1] = 0xfd;
	ethh->d_addr.addr_bytes[2] = 0xfe;
	ethh->d_addr.addr_bytes[3] = 0x9d;
	ethh->d_addr.addr_bytes[4] = 0x23;
	ethh->d_addr.addr_bytes[5] = 0x35;

	/* Dispaly MAC address */
	for (int i = 0; i < 6; i++) {
		printf("%x:", ethh->s_addr.addr_bytes[i]);
	}
	printf("\n");

	packet_ipv4hdr_constructor(iph);

	udph->src_port = htons(45947);
	udph->dst_port = htons(55117);
	udph->dgram_len = htons(L4_LEN);

	/* Init IPv4 and UDP checksum with 0 */
	iph->hdr_checksum = 0;
	udph->dgram_cksum = 0;

	/* Update IPV4 and UDP checksum fields */
#ifdef CKSUM_OFFLOAD
	udph->dgram_cksum = rte_ipv4_phdr_cksum(iph, 0);
	printf("pseudo-header cksum:%x\n", udph->dgram_cksum);
#else
	udph->dgram_cksum = rte_ipv4_udptcp_cksum(iph, udph);
	iph->hdr_checksum = rte_ipv4_cksum(iph);
#endif
}

static void
construct_udp_pkt(uint8_t pid_from)
{
	char *pkt;
	struct rte_mempool *mp;

	mp = mempools[TXRX];
	tx_packet0 = rte_pktmbuf_alloc(mp);
	rte_pktmbuf_reset_headroom(tx_packet0);
	pkt = rte_pktmbuf_mtod(tx_packet0, char *);
	packet_constructor_udp(pkt, pid_from, L4_PAYLOAD_LEN);

	/*update mbuf metadata */
	tx_packet0->pkt_len = L2_LEN;
	tx_packet0->data_len = tx_packet0->pkt_len;
	tx_packet0->nb_segs = 1;
#ifdef CKSUM_OFFLOAD
	tx_packet0->ol_flags = PKT_TX_UDP_CKSUM | PKT_TX_IP_CKSUM;
	//tx_packet0->ol_flags = PKT_TX_UDP_CKSUM;
#else
	tx_packet0->ol_flags = 0;
#endif
	tx_packet0->l2_len = sizeof(struct ether_hdr);
	tx_packet0->l3_len = sizeof(struct ipv4_hdr);
}

static void init_mempool(void)
{

	for(int i = 0; i < 2; i++) {
		mempool_names[i] = (char *)malloc(10);
		snprintf(mempool_names[i], 10, "mempool%d", i);
		mempools[i] = rte_pktmbuf_pool_create(mempool_names[i],
				NMBUF_PER_MEMPOOL, 32, 0, MBUF_SIZE, rte_socket_id());
		if (mempools[i] == NULL) {
			printf("mempool allocation fail!\n");
			exit(1);
		}
	}

	//init_mempool_indir();
}

static void
display_txrx_stats(struct rte_eth_stats *stats, uint16_t nb, const char *name)
{
	printf("%s\nHW statistics:", name);
	printf("error-%lu\trecv-%lu\txmit-%lu\n",
			stats->ierrors, stats->ipackets, stats->opackets);
	printf("SW statistic:%u\n", nb);
}

#ifdef DEBUG
static void
display_segment_stats(uint32_t recv_pkt_len, uint32_t xmit_pkt_len,
		uint32_t origi_len)
{
	printf("recv packet length:%u\txmit segment len:%u\torigi packet len:%u\n",
			recv_pkt_len, xmit_pkt_len, origi_len);
}
#endif

#ifdef DEBUG
static void display_refcnt(struct rte_mbuf *pkt)
{
	printf("refcnt=%u\n", rte_mbuf_refcnt_read(pkt));
}
#endif

static void
tx_loop(uint8_t pid_from)
{
	uint16_t queue_id = 0;
	uint16_t nb_tx = 0;
	struct rte_eth_stats stats;

	/*
	rte_gso_init();
	nb_packets = rte_gso_segment(tx_packet0, PKT_TX_UDP_GSO, MSS,
			mempools[GSO], tx_packets, tx_pkts_sz);
	if (nb_packets == 0) {
		printf("\n\nsegmentation fails, rx_loop stop\n\n");
		exit(1);
	} else
		printf("The given packet has been segmented into %u segments\n", nb_packets);
begin:
	if (nb_packets == 1) {
		printf("No segmentation\n");
		nb_tx = rte_eth_tx_burst(pid_from, queue_id, &tx_packet0, 1);
	} else if (nb_packets == 0) {
		printf("GSO error!\n");
		exit(1);
	} else {
		nb_tx = rte_eth_tx_burst(pid_from, queue_id, tx_packets, nb_packets);
		rte_pktmbuf_free(tx_packet0);
	}
	if (nb_tx <= 0)
		goto begin;

	statistic.tx_pkts += nb_tx;
	rte_eth_stats_get(pid_from, &stats);
	display_txrx_stats(&stats, statistic.tx_pkts, "tx:");
	*/

	for (;;) {
		/*	
		construct_udp_pkt(pid_from);
		nb_packets = rte_gso_segment(tx_packet0, PKT_TX_UDP_GSO, MSS,
				mempools[GSO], tx_packets, tx_pkts_sz);
		if (nb_packets == 0) {
			printf("\n\nsegmentation fails, rx_loop stop\n\n");
			exit(1);
		} else
			printf("The given packet has been segmented into %u segments\n", nb_packets);
		
		// Remember to free the packet
		rte_pktmbuf_free(tx_packet0);

		if (nb_packets == 1) {
			printf("No segmentation\n");
			nb_tx = rte_eth_tx_burst(pid_from, queue_id, &tx_packet0, 1);
		} else if (nb_packets == 0) {
			printf("GSO error!\n");
			exit(1);
		} else
			nb_tx = rte_eth_tx_burst(pid_from, queue_id, tx_packets, nb_packets);
		*/

		sleep(2);
		nb_tx = rte_eth_tx_burst(pid_from, queue_id, &tx_packet0, 1);
		statistic.tx_pkts += nb_tx;
		rte_eth_stats_get(pid_from, &stats);
		if (nb_tx == 0)
			display_txrx_stats(&stats, statistic.tx_pkts, "tx:");
	}
	return;
}

int main(int argc, char **argv)
{
	struct rte_eth_dev_info dev_info;
	const struct rte_eth_txconf *tx_conf;
	uint8_t pid_from;	
	const uint16_t rx_rings = 1, tx_rings = 1;
	struct rte_eth_conf port_conf;
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	nb_ports = rte_eth_dev_count();
	pid_from = 0;
	/*
	if (nb_ports >= 2) {
		pid_from = 1;
		pid_to = 0;
	} else {
		printf("port number is %u, not enough!\n", nb_ports);
		return 0;
	}
	*/
	init_mempool();
	construct_udp_pkt(pid_from);

	port_conf_default.rxmode = rx_mode;
	port_conf_default.txmode = tx_mode;

	port_conf = port_conf_default;
	for (int i = 0; i < 1; i++) {
		ret = rte_eth_dev_configure(i, rx_rings, tx_rings, &port_conf);
		if (ret != 0)
			return ret;
	}

	for (int i = 0; i < rx_rings; i++) {
		ret = rte_eth_rx_queue_setup(pid_from, i, RX_RING_SIZE,
				rte_eth_dev_socket_id(pid_from), NULL, mempools[TXRX]);
		if (ret < 0)
			return ret;
	}

	/* set tx queue txq_flags to support multi-segment mbuf */
	rte_eth_dev_info_get(pid_from, &dev_info);
	dev_info.default_txconf.txq_flags = ETH_TXQ_FLAGS_NOOFFLOADS;
	tx_conf = &dev_info.default_txconf;

	for (int i = 0; i < tx_rings; i++) {
		ret = rte_eth_tx_queue_setup(pid_from, i, TX_RING_SIZE,
				rte_eth_dev_socket_id(pid_from), tx_conf);
		if (ret < 0)
			return ret;
	}

	ret = rte_eth_dev_start(pid_from);
	if (ret < 0)
		return ret;

	rte_eth_promiscuous_enable(pid_from);
	
	tx_loop(pid_from);
	return 0;
}
