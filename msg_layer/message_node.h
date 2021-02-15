#ifndef __POPCORN_MESSAGE_NODE_H__
#define __POPCORN_MESSAGE_NODE_H__

/**
 * Header file to define all of the message node types so they can be used across popcorn
 */

/** TODO: What is the optimum number of nodes? Generally, the higher the 
 *  better but should there be some process in deciding this value?
 */
#define MAX_NUM_NODES_PER_LIST 64 //absolute maximum number of nodes

 struct q_item {
	struct pcn_kmsg_message *msg;
	unsigned long flags;
	struct completion *done;
};

struct message_node {
    uint64_t index;
    bool connected;
	uint32_t address;
	struct sock_handle *handle;
	struct pcn_kmsg_transport *transport;
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


#endif