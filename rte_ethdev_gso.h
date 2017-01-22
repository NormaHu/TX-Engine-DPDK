#ifndef _GSO_H_
#define _GSO_H_

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

#define PKT_TX_UDP_GSO (1<<0)

//We assume these values are host value (little-endian)
#define IPV4_HDR_DF_SHIFT           14
#define IPV4_HDR_MF_SHIFT           13
#define IPV4_HDR_FO_SHIFT           3

#define IPV4_HDR_DF_MASK            (1 << IPV4_HDR_DF_SHIFT)
#define IPV4_HDR_MF_MASK            (1 << IPV4_HDR_MF_SHIFT)
#define IPV4_HDR_FO_MASK            ((1 << IPV4_HDR_FO_SHIFT) - 1)



struct rte_gso_info {
	uint16_t l3_proto;	/* host sequence*/	
	uint16_t l3_len;
	uint32_t gso_size;
};

typedef uint16_t (*rte_gso_segment_fn)(struct rte_mbuf *mbuf,
		uint32_t hdr_offset,
		struct rte_gso_info *info,
		struct rte_mempool *mp,
		struct rte_mbuf **subsegs,
		const uint16_t nb_subsegs);

/*
 *@proto_type: L4 protocol type, defined in Linux
 * */
struct rte_gso_protocol {
	rte_gso_segment_fn gso_segment;
	struct rte_gso_protocol *next;
	uint8_t proto_type;
};
/*
 * All GSO functions are organized as a link-list. gso_offload_l4 
 * points to the first element of the link-list.
 * */
struct rte_gso_protocol *gso_offload_l4;

static inline uint16_t
rte_gso_support_check(uint8_t proto_type)
{
	for (struct rte_gso_protocol *proc = gso_offload_l4;
			proc != NULL; proc = proc->next) {
		if (proc->proto_type & proto_type)
			return 1;
	}
	return 0;
}

void rte_gso_init(void);

uint16_t
rte_gso_segment(struct rte_mbuf *pkt, uint16_t gso_type,
		uint32_t gso_size, 
		struct rte_mempool *mp,
		struct rte_mbuf **subsegs,
		const uint16_t nb_subsegs);

uint16_t
rte_gso_do_segment(struct rte_mbuf *pkt,
		uint32_t hdr_offset,
		uint32_t gso_size,
		struct rte_mempool *mp,
		struct rte_mbuf **subsegs,
		const uint16_t nb_subsegs);

static inline uint8_t
rte_gso_register_protocol(rte_gso_segment_fn gso_func,
		uint8_t proto_type)
{
	struct rte_gso_protocol *handler, *new_proc;
	
	new_proc = (struct rte_gso_protocol *)
		malloc(sizeof(struct rte_gso_protocol));
	new_proc->proto_type = proto_type;
	new_proc->gso_segment = gso_func;
	new_proc->next = NULL;
	
	if (gso_offload_l4 == NULL)
		gso_offload_l4 = new_proc;
	else {
		handler = gso_offload_l4;
		while (handler->next
				&& handler->proto_type != new_proc->proto_type)
			handler = handler->next;

		if (handler->proto_type == new_proc->proto_type) {
			printf("New registered protocol has existed, error\n");
			return 0;
		}
		handler->next = new_proc;
	}
	return 1;
}

static inline uint8_t
rte_gso_remove_protocol(uint8_t proto_type)
{
	struct rte_gso_protocol *handler, *prev;

	handler = gso_offload_l4;

	while (handler && handler->proto_type != proto_type) {
		prev = handler;
		handler = handler->next;
	}

	if (!handler) {
		printf("The given GSO type protocol is NOT found!\n");
		return 0;
	}

	prev->next = handler->next;
	free(handler);
	return 1;
}
#endif
