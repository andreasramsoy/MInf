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
	enum protocol_t protocol; //define acceptable protocols
	struct sock_handle *handle;
	struct pcn_kmsg_transport *transport;
};

#define MAX_NUM_NODES_PER_LIST 64 //absolute maximum number of nodes

struct node_list {
	message_node* nodes[MAX_NUM_NODES_PER_LIST];
	message_list* next_list;
};



int node_list_length = 0;
struct node_list* root_node_list; //Do not access directly! Use get_node(i) function


static char *ip = "N";
module_param(ip,charp, 0000);
MODULE_PARM_DESC(ip, "");

///////////////////////////
///////////////////////////
///////////////////////////
///////////////////////////
///////////////////////////
///////////////////////////  Need to add the node_list transport structure to the pcn_kmsg.c
///////////////////////////  So that the transport structure is actually dynamic
///////////////////////////
///////////////////////////
///////////////////////////
///////////////////////////
///////////////////////////



/* function to access the node_list safely, will return 1 if invalid request
   Also allows for changes in data structure (list to avoid limit of 64 nodes) */
struct message_node* get_node(int index) {
	node_list* list = root_node_list;
	if (index >= node_list_length) goto node_doesnt_exist;
	else {
		//move to the appropriate list
		//List number:       index / MAX_NUM_NODES_PER_LIST
		//Index within list: index % MAX_NUM_NODES_PER_LIST
		int list_number = index / MAX_NUM_NODES_PER_LIST;
		for (int i = 0; i < list_number; i++) {
			#ifdef CONFIG_POPCORN_CHECK_SANITY
					BUG_ON(list->next_list == nullptr); //a list must have been removed without deleting the pointer or updating the length variable
			#endif
			list = list->next_list; //move to next list
		}
		if (list->nodes[index % MAX_NUM_NODES_PER_LIST] == nullptr) {
			goto node_doesnt_exist;
		}
		return list->nodes[index % MAX_NUM_NODES_PER_LIST];
	}

	node_doesnt_exist:
		MSGPRINTK("Attempted to get details of node %d, but it does not exist (only %d exist [indexed from zero] but some may be null)\n", index, node_list_length);
		#ifdef CONFIG_POPCORN_CHECK_SANITY
				BUG_ON(false); //you should never call a node that isn't here
		#endif

		//need better solution for error handling
		//maybe if it requests this node it shows that the node list is out-of-date so reload it and then try again
		return node_list[0]; 
}

struct node_list* create_node_list(node_list *previous_list) { //do not use directly - add_node will use this automatically
	node_list ret = kmalloc(sizeof(node_list));
	if (previous_list != NULL) {
		previous_list.next_list = &ret; //link the previous list to this one
	}
	else {
		MSGPRINTK("A node list was being added but only a null pointer was provided to link it to. Provide the previous list instead\n");
	}
	return &ret;
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
	node_list->nodes[0] = &node0;
	node_list->nodes[1] = &node1;
}

void add_node(message_node node) { //function for adding a single node to the list
	#ifdef CONFIG_POPCORN_CHECK_SANITY
			if (node_list_length != 0) {
				BUG_ON(get_node(node_list_length - 1) != nullptr); //ensure that the previous node has not been used
			}
	#endif
	node_list* list = root_node_list;

	//naviagate to the appropriate list
	int list_number = (node_list_length + 1) / MAX_NUM_NODES_PER_LIST;
	for (int i = 0; i < list_number && list->next_list; i++) {
		list = list->next_list; //move to next list
	}

	//add another list if needed (only adding one at a time as only one node is added at a time)
	if (i < list_number) {
		create_node_list(list);
		list = list->next_list;
	}

	//add to that list
	list->nodes[(node_list_length + 1) % MAX_NUM_NODES_PER_LIST] = &node;
	node_list_length++; //increment here because there are sanity checks that use this variable
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

	//load_node_list(); //populated the node_list

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
