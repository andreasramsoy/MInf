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
#include <popcorn/pcn_kmsg.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/semaphore.h>

#include <popcorn/crypto.h>

/** TODO: What is the optimum number of nodes? Generally, the higher the 
 *  better but should there be some process in deciding this value?
 */
#define MAX_NUM_NODES_PER_LIST 64 //absolute maximum number of nodes
#define NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES 16
#define NODE_LIST_INITAL_TOKEN_ATTEMPTS 5 //number of connections that can attempt to connect before aborting
#define DEFAULT_MAX_CONNECTIONS 20
#define CHECKER_TIMER_MAX_TIME_INTERVAL_MSECS 5 * 1000 * 60
#define CHECKER_TIMER_MIN_TIME_INTERVAL_MSECS 2 * 1000

enum node_list_command_type{NODE_LIST_ADD_NODE_COMMAND, NODE_LIST_REMOVE_NODE_COMMAND};

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
	char token[NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES];
	int bundle_id;
	bool is_connected;
    u8 key[POPCORN_AES_KEY_SIZE]; //key for AES (specific to that node)
    struct crypto_skcipher *transform_obj;
    struct skcipher_request *cipher_request;
};

struct node_list {
	struct message_node* nodes[MAX_NUM_NODES_PER_LIST];
	struct node_list* next_list;
};


#define REMOVED_NODE -1
#define END_OF_NODE_CHANGES -2
#define MAX_TRANSPORT_STRING_LENGTH 15

//data structures for the neighbours
struct neighbour_node_list {
    uint64_t index;
    uint32_t address;
	bool remove;
	char token[NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES];
	char transport[MAX_TRANSPORT_STRING_LENGTH];
	struct neighbour_node_list* next;
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
	struct task_struct* listener;
	struct transport_list* next;
};

extern struct transport_list* transport_list_head;
extern struct node_list* root_node_list; //Do not access directly! Use get_node(i) function
extern struct node_list_info_list_item* root_node_list_info_list;

extern struct semaphore node_list_info_sem;


extern int after_last_node_index;
extern bool registered_on_popcorn_network;
extern int number_of_nodes_to_be_added;
extern char joining_token[NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES];
extern unsigned long time_of_last_change;
extern bool node_list_locked;

void remove_node_core(int index, bool normal_removal);
extern struct message_node* get_node(int index);
extern void run_full_check(void);
extern void run_prelim_check(void);
void send_prelim_check(int their_index);
extern void force_remove_node(int index);
extern void check_and_repair_popcorn(void);
extern struct message_node* create_any_node(struct pcn_kmsg_transport* transport);
extern struct message_node* create_instigator_node(uint32_t address_p);
extern struct message_node* create_node(uint32_t address_p, struct pcn_kmsg_transport* transport);
extern void remove_node(int index);
extern bool add_node_at_position(struct message_node* node, int position, char token[NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES]);
extern int add_node(struct message_node* node, int max_connections, char token[NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES], bool propagate);

extern int find_first_null_pointer(void);
extern bool disable_node(int index);
extern bool enable_node(struct message_node* node);
extern char* protocol_to_string(struct pcn_kmsg_transport* transport);
extern struct pcn_kmsg_transport* string_to_transport(char* protocol);
extern uint32_t address_string_to_int(char* address);

struct message_node* create_node_with_id(uint32_t address_p, struct pcn_kmsg_transport* transport, int index);
struct message_node* create_node_no_enable(uint32_t address_p, struct pcn_kmsg_transport* transport);

extern bool is_myself(struct message_node* node);

extern void send_to_child(int node_index, enum node_list_command_type node_command_type, uint32_t address, char* transport_type, int max_connections, char token[NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES]);
extern void send_node_command_message(int index, enum node_list_command_type command_type, uint32_t address, char* transport_type, int max_connections, char token[NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES]);
extern void send_node_list_info(int their_index, char random_token[NODE_LIST_INFO_RANDOM_TOKEN_SIZE_BYTES]);
extern void send_node_ping_info(int their_index, bool please_echo);
extern int handle_node_ping_info(struct pcn_kmsg_message *msg);
extern int handle_node_check_neighbours_prelim(struct pcn_kmsg_message *msg);

extern unsigned long check_neighbours_checker(void);

int get_prev_neighbour(void);
int get_next_neighbour(void);

extern int add_protocol(struct pcn_kmsg_transport* transport_item);
extern void remove_protocol(struct pcn_kmsg_transport* transport_item);

extern void destroy_node_list(void);
extern bool initialise_node_list(void);

#endif
