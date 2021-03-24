#ifndef __POPCORN_NODE_LIST_H__
#define __POPCORN_NODE_LIST_H__


#define POPCORN_SOCK_ON
//#define POPCORN_RDMA_ON

/*
 * This specifies the structure of the node list and the basic functions
 * to interact with it
 *
 * 
 * This file takes some parts from the old common.h:
 * Copyright (C) 2017 jackchuang <jackchuang@echo3>
 *
 * Distributed under terms of the MIT license.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <popcorn/bundle.h>
#include <popcorn/debug.h>
#include <popcorn/crypto.h>
#include <popcorn/types.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/semaphore.h>

/** TODO: What is the optimum number of nodes? Generally, the higher the 
 *  better but should there be some process in deciding this value?
 */
#define MAX_NUM_NODES_PER_LIST 64 //absolute maximum number of nodes

// encryption
#define AES_KEY_SIZE 256 //currently considered safe (written in 2021), but will increase in future
#define AES_IV_LENGTH 

struct pcn_kmsg_transport; //defined in pcn_kmsg.h

struct q_item {
	struct pcn_kmsg_message *msg;
	unsigned long flags;
	struct completion *done;
};

struct message_node {
    uint64_t index;
    uint32_t address;
    struct sock_handle* handle;
    struct pcn_kmsg_transport* transport;
	enum popcorn_arch arch;
	int bundle_id;
	bool is_connected;
    u8 key[AES_KEY_SIZE]; //key for AES (specific to that node)
    struct crypto_skcipher *transform_obj;
    struct skcipher_request *cipher_request;
};

struct node_list {
	struct message_node* nodes[MAX_NUM_NODES_PER_LIST];
	struct node_list* next_list;
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

struct transport_list { //used to store all of the protocols
	struct pcn_kmsg_transport* transport_structure;
	struct transport_list* next;
};

extern struct transport_list* transport_list_head;
extern struct node_list* root_node_list; //Do not access directly! Use get_node(i) function

extern int after_last_node_index;

extern struct message_node* get_node(int index);
extern struct message_node* create_node(uint32_t address_p, struct pcn_kmsg_transport* transport);
extern void remove_node(int index);
extern int add_node(struct message_node* node, int max_connections);

extern int find_first_null_pointer(void);
extern bool disable_node(int index);
extern bool enable_node(int index);
extern char* protocol_to_string(struct pcn_kmsg_transport* transport);
extern struct pcn_kmsg_transport* string_to_transport(char* protocol);
extern uint32_t address_string_to_int(char* address);

extern bool is_myself(struct message_node* node);


extern int add_protocol(struct pcn_kmsg_transport* transport_item);
extern void remove_protocol(struct pcn_kmsg_transport* transport_item);

extern void destroy_node_list(void);
extern bool initialise_node_list(void);

#endif
