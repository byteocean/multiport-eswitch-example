/*
sudo ./dpdk-flow_offload -l 0,1 -n 2 -r 2 -a 3b:00.0,dv_flow_en=2,dv_esw_en=1,fdb_def_rule_en=1,representor=pf0-1vf0 --vdev=virtio_user0,path=/dev/vhost-net,queue_size=1024,mac=fa:e4:cf:2d:11:b9
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_flow.h>
#include <rte_cycles.h>

static volatile bool force_quit;

#define CHECK_INTERVAL 1000  /* 100ms */
#define MAX_REPEAT_TIMES 90  /* 9s (90 * 100ms) in total */

static uint16_t nr_queues = 1;
struct rte_mempool *mbuf_pool;
struct rte_flow *flow;

static uint16_t main_eswitch_port = 0;
static uint16_t pf_port_id = 1;
static uint16_t vf_port_id = 2;
static uint16_t tap_port_id = 4;

static inline void
print_ether_addr(const char *what, struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", what, buf);
}

static int
pkt_forwarding_loop(void)
{
	struct rte_mbuf *mbufs[32];
	struct rte_ether_hdr *eth_hdr;
	uint16_t nb_rx, sent_count;
	uint16_t i;
	uint16_t j;
	int ret = 0;

	/* Reading the packets from all queues. 8< */
	while (!force_quit) {
		for (i = 0; i < nr_queues; i++) {
			nb_rx = rte_eth_rx_burst(pf_port_id,
						i, mbufs, 32);
			if (nb_rx) {
				sent_count = rte_eth_tx_burst(tap_port_id, 0, (struct rte_mbuf **)mbufs, nb_rx);
				if (unlikely(sent_count != nb_rx)) {
					printf("packet forwarding failed \n");
					ret = -1;
					break;
				}

				for (j = 0; j < nb_rx; j++) {
					struct rte_mbuf *m = mbufs[j];
					// eth_hdr = rte_pktmbuf_mtod(m,
					// 		struct rte_ether_hdr *);
					// // print_ether_addr("src=",
					// 		&eth_hdr->src_addr);
					// print_ether_addr(" - dst=",
					// 		&eth_hdr->dst_addr);
					// printf(" etherframe type is %x \n", ntohs(eth_hdr->ether_type));
					// printf("\n");
					rte_pktmbuf_free(m);
				}
			}
		}

		for (i = 0; i < nr_queues; i++) {
			nb_rx = rte_eth_rx_burst(tap_port_id,
						i, mbufs, 32);
			if (nb_rx) {

				sent_count = rte_eth_tx_burst(pf_port_id, 0, (struct rte_mbuf **)mbufs, nb_rx);
				if (unlikely(sent_count != nb_rx)) {
					printf("packet forwarding failed \n");
					ret = -1;
					break;
				}

				for (j = 0; j < nb_rx; j++) {
					struct rte_mbuf *m = mbufs[j];
					// eth_hdr = rte_pktmbuf_mtod(m,
					// 		struct rte_ether_hdr *);
					// print_ether_addr("src=",
					// 		&eth_hdr->src_addr);
					// print_ether_addr(" - dst=",
					// 		&eth_hdr->dst_addr);
					// printf(" etherframe type is %x \n", ntohs(eth_hdr->ether_type));
					// printf("\n");

					rte_pktmbuf_free(m);
				}
			}
		}
	}
	/* >8 End of reading the packets from all queues. */


	return ret;
}

static void close_all_ports_gracefully(uint16_t nr_ports) {

	struct rte_flow_error error;
	int ret;

	for (int current_port_id = nr_ports - 1; current_port_id >= 0; current_port_id --) {
		uint16_t port_id = (uint16_t)current_port_id;
		rte_flow_flush(port_id, &error);
		ret = rte_eth_dev_stop(port_id);
		if (ret < 0)
			printf("Failed to stop port %u: %s",
		       port_id, rte_strerror(-ret));
		rte_eth_dev_close(port_id);
	}
}

static void
assert_link_status(uint16_t port_id)
{
	struct rte_eth_link link;
	uint8_t rep_cnt = MAX_REPEAT_TIMES;
	int link_get_err = -EINVAL;

	memset(&link, 0, sizeof(link));
	do {
		link_get_err = rte_eth_link_get(port_id, &link);
		if (link_get_err == 0 && link.link_status == RTE_ETH_LINK_UP)
			break;
		rte_delay_ms(CHECK_INTERVAL);
	} while (--rep_cnt);

	if (link_get_err < 0)
		rte_exit(EXIT_FAILURE, ":: error: link get is failing: %s\n",
			 rte_strerror(-link_get_err));
	if (link.link_status == RTE_ETH_LINK_DOWN)
		rte_exit(EXIT_FAILURE, ":: error: link is still down\n");
}

static void enable_isolation_mode(uint16_t port_id) {
	struct rte_flow_error error;
	int ret;

	/* Poisoning to make sure PMDs update it in case of error. */
	memset(&error, 0x66, sizeof(error));
	error.message = "(null)";

	ret = rte_flow_isolate(port_id, 1, &error);
	if (ret < 0) {
		printf("Port cannot be set %d isolated: %s\n",
			error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in rte_flow_isolate");
	}

}

static void enable_promiscuous_mode(uint16_t port_id) {
	int ret;
	ret = rte_eth_promiscuous_enable(port_id);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
				":: promiscuous mode enable failed: err=%s, port=%u\n",
				rte_strerror(-ret), port_id);
}

static void prepare_async_flow_config(uint16_t port_id) {
	struct rte_flow_error error;
	
	struct rte_flow_port_attr port_attr = {
		.nb_aging_objects = 1000,
		.nb_counters = 1000,
	};

	struct rte_flow_queue_attr queue_attr = {
		.size = 500,
	};

	const struct rte_flow_queue_attr *attr_list[1];

	for (uint16_t std_queue = 0; std_queue < 1; std_queue++)
		attr_list[std_queue] = &queue_attr;

	if (rte_flow_configure(port_id, &port_attr, 1, attr_list, &error)<0){
		printf("Flow can't be configured %d message: %s\n",
			error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in rte_flow_configure");
	}
}

/* Port initialization used in flow filtering. 8< */
static void
init_port(uint16_t port_id)
{
	int ret;
	uint16_t i;
	/* Ethernet port configured with default settings. 8< */
	struct rte_eth_conf port_conf = {
		.txmode = {
			.offloads =
				RTE_ETH_TX_OFFLOAD_IPV4_CKSUM  |
				RTE_ETH_TX_OFFLOAD_UDP_CKSUM   |
				RTE_ETH_TX_OFFLOAD_TCP_CKSUM   |
				RTE_ETH_TX_OFFLOAD_TCP_TSO	|
				RTE_ETH_TX_OFFLOAD_IP_TNL_TSO,
		},
	};
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_dev_info dev_info;

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			"Error during getting device (port %u) info: %s\n",
			port_id, strerror(-ret));

	port_conf.txmode.offloads &= dev_info.tx_offload_capa;
	printf(":: initializing port: %d\n", port_id);
	ret = rte_eth_dev_configure(port_id,
				nr_queues, nr_queues, &port_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			":: cannot configure device: err=%d, port=%u\n",
			ret, port_id);
	}

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	/* >8 End of ethernet port configured with default settings. */

	/* Configuring number of RX and TX queues connected to single port. 8< */
	for (i = 0; i < nr_queues; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i, 512,
				     rte_eth_dev_socket_id(port_id),
				     &rxq_conf,
				     mbuf_pool);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Rx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;

	for (i = 0; i < nr_queues; i++) {
		ret = rte_eth_tx_queue_setup(port_id, i, 512,
				rte_eth_dev_socket_id(port_id),
				&txq_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Tx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}
	/* >8 End of Configuring RX and TX queues connected to a port. */

	if (port_id == 0)
		enable_isolation_mode(port_id);

	if (port_id != 0 && port_id != tap_port_id)
		enable_promiscuous_mode(port_id);

	/* Setting the RX port to promiscuous mode. 8< */
	if (port_id != tap_port_id)
		prepare_async_flow_config(port_id);

	/* Starting the port. 8< */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"rte_eth_dev_start:err=%d, port=%u\n",
			ret, port_id);
	}
	/* >8 End of starting the port. */

	assert_link_status(port_id);
	
	printf(":: initialized port: %d done\n", port_id);
}
/* >8 End of Port initialization used in flow filtering. */

static const struct rte_flow_item_ipv6 flow_item_ipv6_dst_mask = {
	// .hdr.dst_addr = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
	.hdr.proto = 0xff,
};

static const struct rte_flow_item_eth flow_item_eth_mask = {
	.hdr.ether_type = 0xffff,
};

/****data structures to store flow rule related configuration****/
#define MAX_NR_OF_PATTERN_TEMPLATE 1
#define MAX_NR_OF_ACTION_TEMPLATE 2

// static struct rte_flow_template_table *table;
// static struct rte_flow_template_table *table_second;

static struct rte_flow_pattern_template_attr pattern_attr = {.transfer = 1};
static struct rte_flow_actions_template_attr action_attr = {.transfer = 1};

static struct rte_flow_item_ethdev represented_port_mask = {.port_id = 0xffff};

static struct rte_flow_template_table_attr table_attr_pf = {
		.flow_attr.transfer = 1,
		.nb_flows = 2,
		.specialize = RTE_FLOW_TABLE_SPECIALIZE_TRANSFER_WIRE_ORIG,
};

static	struct rte_flow_template_table_attr table_attr_vf = {
		.flow_attr.transfer = 1,
		.nb_flows = 2,
		.specialize = RTE_FLOW_TABLE_SPECIALIZE_TRANSFER_VPORT_ORIG,
};


struct port_template_info {
	uint8_t port_id;
	struct rte_flow_pattern_template *pattern_templates[MAX_NR_OF_PATTERN_TEMPLATE];
	struct rte_flow_actions_template *actions_templates[MAX_NR_OF_ACTION_TEMPLATE];

	struct rte_flow_template_table *template_table; // only one table and it is too specific for a flow rule
};

static struct port_template_info port_template_info_pf = {
	// .port_id = pf_port_id,
};

static struct port_template_info port_template_info_vf = {
	// .port_id = vf_port_id,
};

static struct rte_flow_pattern_template* create_pattern_template(uint16_t port_id, const struct rte_flow_item pattern[]) {
	struct rte_flow_pattern_template *pattern_template;
	struct rte_flow_error error;

	pattern_template = rte_flow_pattern_template_create(port_id, &pattern_attr, pattern, &error);

	if (!pattern_template) {
		printf("Flow pattern can't be created %d message: %s\n",
			error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in rte_flow_pattern_template_create");
	}

    return pattern_template;
}

static struct rte_flow_actions_template* create_actions_template(uint16_t port_id, const struct rte_flow_action act[], const struct rte_flow_action msk[]) {
	struct rte_flow_actions_template *actions_template;
	struct rte_flow_error error;

	actions_template =
			rte_flow_actions_template_create(port_id, &action_attr, act, msk, &error);
	if (!actions_template) {
		printf("Flow action template can't be created %d message: %s\n",
			error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in rte_flow_actions_template_create");
	}

    return actions_template;
}

static struct rte_flow_template_table* create_table_template(uint16_t port_id, struct rte_flow_template_table_attr *table_attr, struct rte_flow_pattern_template* pattern_templates[], int nb_pattern_templ, struct rte_flow_actions_template* actions_templates[], int nb_actions_templ) {
    struct rte_flow_error error;
	struct rte_flow_template_table *table;
	
	table = rte_flow_template_table_create(port_id, table_attr, pattern_templates, nb_pattern_templ, actions_templates, nb_actions_templ, &error);
	
	if (!table) {
		printf("Template table can't be created %d message: %s\n",
			error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in rte_flow_template_table_create");
	}
	
    return table;
}

static void create_templates_for_pf (void) {

	// pattern template
	struct rte_flow_item pattern[] = {
		[0] = {.type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT, .mask = &represented_port_mask},
		[1] = {.type = RTE_FLOW_ITEM_TYPE_ETH, .mask = &flow_item_eth_mask},
		[2] = {.type = RTE_FLOW_ITEM_TYPE_IPV6, .mask = &flow_item_ipv6_dst_mask},
		[3] = {.type = RTE_FLOW_ITEM_TYPE_END,},
	}; // this pattern template does not seem need to be changed. Different IPv6 addresses can be concretised later?

	port_template_info_pf.pattern_templates[0] = create_pattern_template(main_eswitch_port, pattern);

	// first action template
	struct rte_ether_hdr eth_hdr_mask = {
		// .dst_addr.addr_bytes = "\xd2\xfb\x07\x7f\xa9\x3a",
		.dst_addr.addr_bytes = "\x66\x9d\xa7\xfd\xfb\x43",
		.src_addr.addr_bytes = "\x11\x22\x33\x44\x55\x66",
		.ether_type = htons(0x0800),
	};

	struct rte_flow_action_raw_decap decap_mask = {.size = (sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv6_hdr))};
	struct rte_flow_action_raw_encap encap_mask = {.data = (uint8_t *)&eth_hdr_mask, .size = sizeof(struct rte_ether_hdr)};

	struct rte_flow_action act[] = {
		[0] = {.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP, .conf = &decap_mask},
		[1] = {.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP, .conf = &encap_mask},
		[2] = {.type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,},
		[3] = {.type = RTE_FLOW_ACTION_TYPE_END,},
	};

	struct rte_flow_action msk[] = {
		[0] = {.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP, .conf= &decap_mask},
		[1] = {.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP, .conf= &encap_mask},
		[2] = {.type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,},
		[3] = {.type = RTE_FLOW_ACTION_TYPE_END,},
	};

	port_template_info_pf.actions_templates[0] = create_actions_template(main_eswitch_port, act, msk);

	// second action template -- not used, but to test the case multiple co-existing action templates
	struct rte_ether_hdr eth_hdr_mask_extra = {
		.dst_addr.addr_bytes = "\x77\x9d\xa7\xfd\xfb\x99", // different mac address
		.src_addr.addr_bytes = "\x11\x22\x33\x44\x55\x66",
		.ether_type = htons(0x0800),
	}; // this action template needs to be tested against different dst mac address due to sending to different VMs.

	struct rte_flow_action_raw_decap decap_mask_extra = {.size = (sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv6_hdr))};
	struct rte_flow_action_raw_encap encap_mask_extra = {.data = (uint8_t *)&eth_hdr_mask_extra, .size = sizeof(struct rte_ether_hdr)};


	struct rte_flow_action act_extra[] = {
		[0] = {.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP, .conf = &decap_mask_extra},
		[1] = {.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP, .conf = &encap_mask_extra},
		[2] = {.type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,},
		[3] = {.type = RTE_FLOW_ACTION_TYPE_END,},
	};

	struct rte_flow_action msk_extra[] = {
		[0] = {.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP, .conf= &decap_mask_extra},
		[1] = {.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP, .conf= &encap_mask_extra},
		[2] = {.type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,},
		[3] = {.type = RTE_FLOW_ACTION_TYPE_END,},
	};

	port_template_info_pf.actions_templates[1] = create_actions_template(main_eswitch_port, act_extra, msk_extra);

	// create template table
	port_template_info_pf.template_table = create_table_template(main_eswitch_port, &table_attr_pf,
					(struct rte_flow_pattern_template **)&port_template_info_pf.pattern_templates, MAX_NR_OF_PATTERN_TEMPLATE,
					(struct rte_flow_actions_template **)&port_template_info_pf.actions_templates, MAX_NR_OF_ACTION_TEMPLATE);
}

static void create_templates_for_vf(void) {
	
	// create pattern template
	struct rte_flow_item pattern[] = {
		[0] = {.type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT, .mask = &represented_port_mask},
		[1] = {.type = RTE_FLOW_ITEM_TYPE_ETH, .mask = &flow_item_eth_mask},
		[2] = {.type = RTE_FLOW_ITEM_TYPE_END,},
	};

	port_template_info_vf.pattern_templates[0] = create_pattern_template(main_eswitch_port, pattern);

	// create action template
	
	uint8_t encap_hdr_buffer[(sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv6_hdr))]={0};
	// uint8_t encap_hdr_buffer_empty[(sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv6_hdr))]={0xff};

	struct rte_ether_hdr *eth_hdr_mask_vf2pf = (struct rte_ether_hdr *)encap_hdr_buffer;

	// Setting destination MAC address
	// uint8_t dst_mac_addr[] = {0x90, 0x3c, 0xb3, 0x33, 0x72, 0xfb}; // mac address on switch port connected with pf0
	uint8_t dst_mac_addr[] = {0x90, 0x3c, 0xb3, 0x33, 0x83, 0xfb}; // mac address on switch port connected with pf1
	memcpy(eth_hdr_mask_vf2pf->dst_addr.addr_bytes, dst_mac_addr, RTE_ETHER_ADDR_LEN);

	// Setting source MAC address
	// uint8_t src_mac_addr[] = {0x04, 0x3f, 0x72, 0xe8, 0xcf, 0xca}; // mac address of pf0
	uint8_t src_mac_addr[] = {0x04, 0x3f, 0x72, 0xe8, 0xcf, 0xcb}; // mac address of pf1
	memcpy(eth_hdr_mask_vf2pf->src_addr.addr_bytes, src_mac_addr, RTE_ETHER_ADDR_LEN);

	eth_hdr_mask_vf2pf->ether_type = htons(RTE_ETHER_TYPE_IPV6);

	struct rte_ipv6_hdr *ipv6_hdr_mask_vf2pf = (struct rte_ipv6_hdr *)(eth_hdr_mask_vf2pf + 1);
	// change the ipv6 address to the actual address of your destination
	uint8_t ipv6_dst_addr[] = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
	// change the ipv6 address to the actual address of your source
	uint8_t ipv6_src_addr[] = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};


	memcpy(ipv6_hdr_mask_vf2pf->dst_addr, ipv6_dst_addr, sizeof(ipv6_dst_addr));
	memcpy(ipv6_hdr_mask_vf2pf->src_addr, ipv6_src_addr, sizeof(ipv6_src_addr));
	ipv6_hdr_mask_vf2pf->proto = IPPROTO_IPIP;
	ipv6_hdr_mask_vf2pf->vtc_flow = htonl(0x60000000);
	ipv6_hdr_mask_vf2pf->payload_len = 0;
	ipv6_hdr_mask_vf2pf->hop_limits = 0x40;


	struct rte_flow_action_raw_decap decap_mask_vf2pf = {.size = sizeof(struct rte_ether_hdr)};
	struct rte_flow_action_raw_encap encap_mask_vf2pf = {.data = (uint8_t *)encap_hdr_buffer, .size = (sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv6_hdr))};
	// struct rte_flow_action_raw_encap encap_mask_vf2pf = {.data = NULL, .size = (sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv6_hdr))};


	struct rte_flow_action act_vf2pf[] = {
		[0] = {.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP, .conf = &decap_mask_vf2pf},
		// [1] = {.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP, },
		[1] = {.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP, .conf = &encap_mask_vf2pf},
		[2] = {.type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,},
		[3] = {.type = RTE_FLOW_ACTION_TYPE_END,},
	};

	struct rte_flow_action msk_vf2pf[] = {
		[0] = {.type = RTE_FLOW_ACTION_TYPE_RAW_DECAP, .conf= &decap_mask_vf2pf},
		// [1] = {.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP, },
		[1] = {.type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP, .conf= &encap_mask_vf2pf},
		[2] = {.type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,},
		[3] = {.type = RTE_FLOW_ACTION_TYPE_END,},
	};

	port_template_info_vf.actions_templates[0] = create_actions_template(main_eswitch_port, act_vf2pf, msk_vf2pf);


	// create template table
	port_template_info_vf.template_table = create_table_template(main_eswitch_port, &table_attr_vf,
					(struct rte_flow_pattern_template **)&port_template_info_vf.pattern_templates, MAX_NR_OF_PATTERN_TEMPLATE,
					(struct rte_flow_actions_template **)&port_template_info_vf.actions_templates, MAX_NR_OF_ACTION_TEMPLATE - 1);
}

static void create_concrete_rules_for_pf(void) {
	
	struct rte_flow_error error;
	struct rte_flow_item_eth eth_pattern = {.type = htons(0x86DD)};

	uint8_t dst_addr[] =  {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
	struct rte_flow_item_ipv6 ipv6_hdr = {0};
	ipv6_hdr.hdr.proto = IPPROTO_IPIP;
	memcpy(ipv6_hdr.hdr.dst_addr, dst_addr, sizeof(dst_addr));

	struct rte_flow_item_ethdev represented_port = {.port_id = pf_port_id};

	struct rte_flow_item concrete_patterns[4];

	concrete_patterns[0].type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT;
	concrete_patterns[0].spec = &represented_port;
	concrete_patterns[0].mask = NULL;
	concrete_patterns[0].last = NULL;


	concrete_patterns[1].type = RTE_FLOW_ITEM_TYPE_ETH;
	concrete_patterns[1].spec = &eth_pattern;
	concrete_patterns[1].mask = NULL;
	concrete_patterns[1].last = NULL;

	concrete_patterns[2].type = RTE_FLOW_ITEM_TYPE_IPV6;
	concrete_patterns[2].spec = &ipv6_hdr;
	concrete_patterns[2].mask = NULL;
	concrete_patterns[2].last = NULL;

	concrete_patterns[3].type = RTE_FLOW_ITEM_TYPE_END;
	concrete_patterns[3].spec = NULL;
	concrete_patterns[3].mask = NULL;
	concrete_patterns[3].last = NULL;

	struct rte_flow_action_ethdev port_action = {
		.port_id = vf_port_id,
	};
	
	struct rte_flow_action concrete_actions[4];

	// struct rte_ether_hdr eth_hdr = {
	// 	.dst_addr.addr_bytes = "\x66\x9d\xa7\xfd\xfb\x43",
	// 	.src_addr.addr_bytes = "\x22\x22\x33\x44\x55\x66",
	// 	.ether_type = htons(0x0800),
	// };
	struct rte_flow_action_raw_decap raw_decap_action={0};
	// raw_decap_action.data = NULL;
	// raw_decap_action.size = sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv6_hdr);

	concrete_actions[0].type = RTE_FLOW_ACTION_TYPE_RAW_DECAP;
	concrete_actions[0].conf = &raw_decap_action;
	

 	struct rte_flow_action_raw_encap raw_encap_action={0};
	// raw_encap_action.data = (uint8_t *)&eth_hdr;
	// raw_encap_action.size = sizeof(struct rte_ether_hdr);

	concrete_actions[1].type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP;
	concrete_actions[1].conf = &raw_encap_action;

	concrete_actions[2].type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT;
	concrete_actions[2].conf = &port_action;

	concrete_actions[3].type = RTE_FLOW_ACTION_TYPE_END;
	concrete_actions[3].conf = NULL;


	struct rte_flow *flow;
	struct rte_flow_op_attr op_attr = {0};
	flow = rte_flow_async_create(main_eswitch_port, 0, &op_attr, port_template_info_pf.template_table,
			concrete_patterns, 0, concrete_actions, 0, NULL, &error);

	if (!flow) {
		printf("Flow insertion can't be done %d message: %s\n",
			error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "pf: error in rte_flow_async_create");
	}

	printf("installed concrete flow for pf\n");

}

static void create_concrete_rules_for_vf(void) {

	struct rte_flow_error error;
	struct rte_flow_item_eth eth_pattern_vf2pf = {.type = htons(0x0800)};


	struct rte_flow_item_ethdev represented_port_vf2pf = {.port_id = vf_port_id};

	struct rte_flow_item concrete_patterns_vf2pf[3];

	concrete_patterns_vf2pf[0].type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT;
	concrete_patterns_vf2pf[0].spec = &represented_port_vf2pf;
	concrete_patterns_vf2pf[0].mask = NULL;
	concrete_patterns_vf2pf[0].last = NULL;


	concrete_patterns_vf2pf[1].type = RTE_FLOW_ITEM_TYPE_ETH;
	concrete_patterns_vf2pf[1].spec = &eth_pattern_vf2pf;
	concrete_patterns_vf2pf[1].mask = NULL;
	concrete_patterns_vf2pf[1].last = NULL;


	concrete_patterns_vf2pf[2].type = RTE_FLOW_ITEM_TYPE_END;
	concrete_patterns_vf2pf[2].spec = NULL;
	concrete_patterns_vf2pf[2].mask = NULL;
	concrete_patterns_vf2pf[2].last = NULL;

	struct rte_flow_action_ethdev port_action_vf2pf = {
		.port_id = pf_port_id,
	};
	
	struct rte_flow_action concrete_actions_vf2pf[4];

	struct rte_flow_action_raw_decap raw_decap_action_vf2pf={0};
	// raw_decap_action_vf2pf.data = NULL;
	raw_decap_action_vf2pf.size = sizeof(struct rte_ether_hdr);

	concrete_actions_vf2pf[0].type = RTE_FLOW_ACTION_TYPE_RAW_DECAP;
	concrete_actions_vf2pf[0].conf = &raw_decap_action_vf2pf;
	

 	struct rte_flow_action_raw_encap raw_encap_action ={0};
 	// struct rte_flow_action_raw_encap raw_encap_action_test={0};
	// raw_encap_action_test.data = encap_hdr_buffer;
	// raw_encap_action_test.size = sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv6_hdr);

	concrete_actions_vf2pf[1].type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP;
	// concrete_actions_vf2pf[1].conf = &raw_encap_action_test;
	concrete_actions_vf2pf[1].conf = &raw_encap_action; // it is an empty action, derived from template though.

	concrete_actions_vf2pf[2].type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT;
	concrete_actions_vf2pf[2].conf = &port_action_vf2pf;

	concrete_actions_vf2pf[3].type = RTE_FLOW_ACTION_TYPE_END;
	concrete_actions_vf2pf[3].conf = NULL;


	struct rte_flow *flow_vf2pf;
	struct rte_flow_op_attr op_attr = {0};
	flow_vf2pf = rte_flow_async_create(main_eswitch_port, 0, &op_attr, port_template_info_vf.template_table,
			concrete_patterns_vf2pf, 0, concrete_actions_vf2pf, 0, NULL, &error);

	if (!flow_vf2pf) {
		printf("Flow insertion can't be done %d message: %s\n",
			error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in rte_flow_async_create");
	}

	printf("installed concrete flow for vf \n");
}


static void push_all_rules(void) {

	struct rte_flow_error error;

	int ret = rte_flow_push(main_eswitch_port, 0, &error);
	if (ret < 0) {
		printf("Flow cannot be pushed %d message: %s\n",
			error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in rte_flow_push");
	}
}

static void install_flow_rules(void) {

	port_template_info_pf.port_id = pf_port_id;
	port_template_info_vf.port_id = vf_port_id;

	create_templates_for_pf();
	create_templates_for_vf();

	create_concrete_rules_for_pf();
	create_concrete_rules_for_vf();

	push_all_rules();
}


static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

static void print_async_related_config(uint16_t port_id) {
	struct rte_flow_port_info port_info;
	struct rte_flow_queue_info queue_info;
	struct rte_flow_error error;

	if (rte_flow_info_get(port_id, &port_info, &queue_info, &error)<0){
		printf("Flow can't be created %d message: %s\n",
			error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in rte_flow_info_get");
	}

	printf(" queue nr: %u \n", port_info.max_nb_queues);
	printf(" max_nb_counters: %u \n", port_info.max_nb_counters);
	printf(" max_nb_aging_objects: %u \n", port_info.max_nb_aging_objects);
}

int
main(int argc, char **argv)
{
	int ret;
	uint16_t nr_ports;

	/* Initialize EAL. 8< */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, ":: invalid EAL arguments\n");
	/* >8 End of Initialization of EAL. */

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, ":: no Ethernet ports found\n");


	/* Allocates a mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", 4096, 128, 0,
					    RTE_MBUF_DEFAULT_BUF_SIZE,
					    rte_socket_id());
	/* >8 End of allocating a mempool to hold the mbufs. */
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");


	/* Initializing all the ports using the user defined init_port(). 8< */
	for (uint16_t current_port = 0; current_port < nr_ports; current_port++) {
		init_port(current_port);
	}

	install_flow_rules();


	ret = pkt_forwarding_loop();

	close_all_ports_gracefully(nr_ports);

	/* clean up the EAL */
	rte_eal_cleanup();

	return ret;
}
