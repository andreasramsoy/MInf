/*
 * common.h
 * Copyright (C) 2017 jackchuang <jackchuang@echo3>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef _MSG_LAYER_COMMON_H_
#define _MSG_LAYER_COMMON_H_

#include <popcorn/pcn_kmsg.h>
#include <popcorn/bundle.h>
#include <popcorn/debug.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>

#include "config.h"

struct q_item {
	struct pcn_kmsg_message *msg;
	unsigned long flags;
	struct completion *done;
};

/* Per-node handle for socket */
struct sock_handle {
	int nid;

	/* Ring buffer for queueing outbound messages */
	struct q_item *msg_q;
	unsigned long q_head;
	unsigned long q_tail;
	spinlock_t q_lock;
	struct semaphore q_empty;
	struct semaphore q_full;

	struct socket *sock;
	struct task_struct *send_handler;
	struct task_struct *recv_handler;
};

struct message_node {
	uint32_t address;
	bool enabled;
	//protocol_type protocol; //define acceptable protocols
	struct sock_handle *handle;
	struct pcn_kmsg_transport *transport;
};


#define MAX_NUM_NODES 64 //absolute maximum number of nodes

int node_list_length = 0;
struct message_node* node_list[MAX_NUM_NODES] = {}; //Do not access directly! Use get_node(i) function


static char *ip = "N";
module_param(ip,charp, 0000);
MODULE_PARM_DESC(ip, "");

/* function to access the node_list safely, will return 1 if invalid request
   Also allows for changes in data structure (list to avoid limit of 64 nodes) */
struct message_node* get_node(int index) {
	if (index >= node_list_length) {
		MSGPRINTK("Attempted to get details of node %d, but only %d exist (indexed from zero)\n", index, node_list_length);
		/*
				Decide what should be done in the event of an error? *****************
		*/
		return node_list[0]; //need better solution for error handling, maybe if it requests this node it shows that the node list is out-of-date so reload it and then try again
	}
	else {
		return node_list[index];
	}
}

void load_node_list(void) {
	MSGPRINTK("Populating the list of nodes\n");
	/*
		Stub for getting this data from a file, nodes are currently hard-coded
	*/
	node_list_length = 2; ///////REMEMBER TO UPDATE THE MAX_NUM_NODES

	struct message_node node0 = {
		.address = in_aton("192.168.10.100"),
		.enabled = true,
	};
	struct message_node node1 = {
		.address = in_aton("192.168.10.101"),
		.enabled = true,
	};
	node_list[0] = &node0;
	node_list[1] = &node1;
}

void node_list_destroy(void) {
	/*
		Nothing within the node list is currently called with kalloc
	*/
}

static uint32_t __init __get_host_ip(void)
{
	struct net_device *d;
	for_each_netdev(&init_net, d) {
		struct in_ifaddr *ifaddr;

		for (ifaddr = d->ip_ptr->ifa_list; ifaddr; ifaddr = ifaddr->ifa_next) {
			int i;
			uint32_t addr = ifaddr->ifa_local;
			for (i = 0; i < MAX_NUM_NODES; i++) {
				if (addr == get_node(i)->address) {
					return addr;
				}
			}
		}
	}
	return -1;
}

bool __init identify_myself(void)
{
	int i;
	uint32_t my_ip;
	/*printk("%s\n",ip);
	if(ip[0]=='N'){
		PCNPRINTK("Loading default node configuration...\n");

		for (i = 0; i < MAX_NUM_NODES; i++) {
			ip_table[i] = in_aton(ip_addresses[i]);
		}
	}
	else{
		PCNPRINTK("Loading user configuration...\n");
		int j, k = 0;
		char* tem, *temp;

		// for (i = 0; i < MAX_NUM_NODES; i++) {
		// 	tem = (char*)kmalloc(15*sizeof(char),GFP_KERNEL);
		// 	for(j = 0; j< 16; j++) {
		// 		if( k == strlen(ip)) {i==MAX_NUM_NODES; break;}
		// 		if (ip[k]==':'){ k++;break;} else {tem[j] = ip[k]; k++;}
		// 	}
			
		// 	printk("tem[%d] %s\n",i,tem);
		// 	ip_table[i] = in_aton(tem);
		// }
		// for (i = 0; i < MAX_NUM_NODES; i++) {
        //                 printk("%zu\n",ip_table[i]);
        //         }

		temp=strlen(ip) + ip;
		while (tem = strchrnul(ip, ',')) {
			*tem = 0;
			ip_table[k++].address = in_aton(ip);
			ip=tem+1;
			if (ip > temp)
				break;
		}
	}*/

	load_node_list(); //populated the node_list

	my_ip = __get_host_ip();

	for (i = 0; i < MAX_NUM_NODES; i++) {
		char *me = " ";
		if (my_ip == get_node(i)->address) {
			my_nid = i;
			me = "*";
		}
		PCNPRINTK("%s %d: %pI4\n", me, i, get_node(i)->address);
	}

	if (my_nid < 0) {
		PCNPRINTK_ERR("My IP is not listed in the node configuration\n");
		return false;
	}

	return true;
}
#endif
