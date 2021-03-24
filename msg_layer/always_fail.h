/**
 * Headerfile that creates the no transport structure, this causing sending of
 * messages to fail without additional checks being needed on functions
 */

#ifndef __POPCORN_ALWAYS_FAIL_TRANSPORT__
#define __POPCORN_ALWAYS_FAIL_TRANSPORT__


//check with Antonio and Karim what they think about this idea before updating rest of code

struct pcn_kmsg_transport {
	.name = "always_fail",
	features = 0;

	.is_initalised = true;
	int number_of_users = 0; //number of nodes currently using this transport
	int (*init_transport)(void); //one time initialisation
	int (*exit_transport)(void); //final destroying of the transport
	bool (*init_node)(struct message_node*); //called for each node that joins
	bool (*kill_node)(struct message_node*); //called for each node removed
	int (*connect)(struct message_node*);
	int (*accept)(struct message_node*);

	struct pcn_kmsg_message *(*get)(size_t);
	void (*put)(struct pcn_kmsg_message *);

	int (*send)(int, struct pcn_kmsg_message *, size_t);
	int (*post)(int, struct pcn_kmsg_message *, size_t);
	void (*done)(struct pcn_kmsg_message *);

	void (*stat)(struct seq_file *, void *);

    #ifdef POPCORN_RDMA_ON
	struct pcn_kmsg_rdma_handle *(*pin_rdma_buffer)(void *, size_t);
	void (*unpin_rdma_buffer)(struct pcn_kmsg_rdma_handle *);
	int (*rdma_write)(int, dma_addr_t, void *, size_t, u32);
	int (*rdma_read)(int, void *, dma_addr_t, size_t, u32);
    #endif
};

static int __init init_always_fail(void) {
	
}

#endif