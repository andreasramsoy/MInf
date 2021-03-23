/*
 * pcn_kmesg.c - Kernel Module for Popcorn Messaging Layer over Socket
 */

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/err.h>

#include <popcorn/pcn_kmsg.h>
#include <popcorn/debug.h>
#include <popcorn/stat.h>
#include <popcorn/bundle.h>
#include <popcorn/crypto.h>
#include <popcorn/node_list.h> //to access the node list

static pcn_kmsg_cbftn pcn_kmsg_cbftns[PCN_KMSG_TYPE_MAX] = { NULL };

static struct pcn_kmsg_transport *transport = NULL;

/**
 * TODO: Remove following function (ensure that nothing breaks from removing it first)
 */
void pcn_kmsg_set_transport(struct pcn_kmsg_transport *tr)
{
	if (transport && tr) {
		printk(KERN_ERR "Replace hot transport at your own risk.\n");
	}
	transport = tr;
}
EXPORT_SYMBOL(pcn_kmsg_set_transport);

int pcn_kmsg_register_callback(enum pcn_kmsg_type type, pcn_kmsg_cbftn callback)
{
	BUG_ON(type < 0 || type >= PCN_KMSG_TYPE_MAX);

	pcn_kmsg_cbftns[type] = callback;
	return 0;
}
EXPORT_SYMBOL(pcn_kmsg_register_callback);

int pcn_kmsg_unregister_callback(enum pcn_kmsg_type type)
{
	return pcn_kmsg_register_callback(type, (pcn_kmsg_cbftn)NULL);
}
EXPORT_SYMBOL(pcn_kmsg_unregister_callback);

#ifdef CONFIG_POPCORN_CHECK_SANITY
static atomic_t __nr_outstanding_requests[PCN_KMSG_TYPE_MAX] = { ATOMIC_INIT(0) };
#endif

#ifdef POPCORN_ENCRYPTION_ON
void pcn_kmsg_process(struct pcn_kmsg_message_encrypted *encrypted_msg)
#else
void pcn_kmsg_process(struct pcn_kmsg_message *msg)
#endif
{
	pcn_kmsg_cbftn ftn;

#ifdef POPCORN_ENCRYPTION_ON
	//translate pcn_kmsg_message_encrypted to be pcn_kmsg_message

	struct pcn_kmsg_message *msg;
	int error;
	struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
	struct message_node* node = get_node(encrypted_msg->from_nid);
	if (node == NULL) {
		printk(KERN_ERR "The message could not be encrypted as it was sent from node %d which does not exist\n", encrypted_msg->from_nid);
		goto decryption_fail;
	}

	sg_init_one(&sg, encrypted_msg->data, datasize);
	skcipher_request_set_callback(node->cipher_request, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
	skcipher_request_set_crypt(node->cipher_request, &sg, &sg, sizeof(struct pcn_kmsg_message), msg->iv);
	error = crypto_wait_req(crypto_skcipher_decrypt(node->cipher_request), &wait);
	if (error) {
			printk(KERN_ERR "Error decrypting data: %d, from node %d\n", error, msg->from_nid);
			goto decryption_fail;
	}
	msg = encrypted_msg->data; //copy the encrypted data to the msg for processing

	//now ready to process msg as normal
#endif

#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(msg->header.type < 0 || msg->header.type >= PCN_KMSG_TYPE_MAX);
	BUG_ON(msg->header.size < 0 || msg->header.size > PCN_KMSG_MAX_SIZE);
	if (atomic_inc_return(__nr_outstanding_requests + msg->header.type) > 64) {
		if (WARN_ON_ONCE("leaking received messages, ")) {
			printk("type %d\n", msg->header.type);
		}
	}
#endif

	account_pcn_message_recv(msg);

	ftn = pcn_kmsg_cbftns[msg->header.type];

	if (ftn != NULL) {
		ftn(msg);
	} else {
		printk(KERN_ERR"No callback registered for %d\n", msg->header.type);
		#ifndef POPCORN_ENCRYPTION_ON
		pcn_kmsg_done(msg);
		#endif
	}

	#ifdef POPCORN_ENCRYPTION_ON
decryption_fail:
	crypto_free_skcipher(transform_obj);
    skcipher_request_free(cipher_request);
	pcn_kmsg_done(encrypted_msg);
	#endif
}
EXPORT_SYMBOL(pcn_kmsg_process);


static inline int __build_and_check_msg(enum pcn_kmsg_type type, int to, struct pcn_kmsg_message *msg, size_t size)
{
#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(type < 0 || type >= PCN_KMSG_TYPE_MAX);
	BUG_ON(size > PCN_KMSG_MAX_SIZE);
	BUG_ON(to < 0 || to >= MAX_POPCORN_NODES);
	BUG_ON(to == my_nid);
#endif

	msg->header.type = type;
	msg->header.prio = PCN_KMSG_PRIO_NORMAL;
	msg->header.size = size;
	msg->header.from_nid = my_nid;
	return 0;
}

#ifdef POPCORN_ENCRYPTION_ON
static inline int __build_and_check_msg_encrypted(enum pcn_kmsg_type type, int to, struct pcn_kmsg_message_encrypted *msg, size_t size)
{
	int error;
	struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
	struct message_node* node = get_node(to);

	if (get_node(to) == NULL) {
		printk(KERN_ERR "Trying to build message for node that does not exist\n");
		goto encrption_fail;
	}

	msg->from_nid = my_nid;
	get_random_bytes(msg->iv, AES_IV_LENGTH);

	//build the message as normal
	if ((ret = __build_and_check_msg(type, to, msg->data, size))) return ret;

	//encrypt the message (setup is done on node initialisation to save time)
	sg_init_one(&sg, encrypted_msg->data, datasize);
	skcipher_request_set_callback(node->cipher_request, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
	skcipher_request_set_crypt(node->cipher_request, &sg, &sg, sizeof(struct pcn_kmsg_message), msg->iv);
	error = crypto_wait_req(crypto_skcipher_decrypt(node->cipher_request), &wait);
	if (error) {
			printk(KERN_ERR "Error decrypting data: %d, from node %d\n", error, msg->from_nid);
			goto encryption_fail;
	}
	msg = encrypted_msg->data; //copy the encrypted data to the msg for processing

	//now ready to process msg as normal

encryption_fail:
	printk(KERN_ERR "Error encrypting, abort message!\n");
	return 1;
}
#endif

int pcn_kmsg_send(enum pcn_kmsg_type type, int to, void *msg, size_t size)
{
	int ret;
	u8 iv[AES_IV_LENGTH];
	if ((ret = __build_and_check_msg(type, to, msg, size))) return ret;

	account_pcn_message_sent(msg);
	
	printk(KERN_DEBUG "PCN_KMSG_SEND!\n");
	if (to == my_nid) {
		printk(KERN_ERR "Should never send message to yourself! Abort message.\n");
		return 1;
	}
	
	return get_node(to)->transport->send(to, msg, size);
}
EXPORT_SYMBOL(pcn_kmsg_send);

int pcn_kmsg_post(enum pcn_kmsg_type type, int to, void *msg, size_t size)
{
	int ret;
	if ((ret = __build_and_check_msg(type, to, msg, size))) return ret;

	account_pcn_message_sent(msg);
	printk(KERN_DEBUG "PCN_KMSG_POST!\n");
	if (to == my_nid) {
		printk(KERN_ERR "Should never post message to yourself! Abort message.\n");
		return 1;
	}
	
	return get_node(to)->transport->post(to, msg, size);
}
EXPORT_SYMBOL(pcn_kmsg_post);

void *pcn_kmsg_get(size_t size)
{
	////////////////////////////////////////////////////////////////////////////////////////////////

	printk(KERN_DEBUG "PCN_KMSG_GET!\n");
	if (transport && transport->get)
		return transport->get(size);
	
	return kmalloc(size, GFP_KERNEL);
}
EXPORT_SYMBOL(pcn_kmsg_get);

void pcn_kmsg_put(void *msg)
{
	////////////////////////////////////////////////////////////////////////////////////////////////same as above function
	printk(KERN_DEBUG "PCN_KMSG_PUT!\n");
	if (transport && transport->put) {
		transport->put(msg);
	} else {
		kfree(msg);
	}
}
EXPORT_SYMBOL(pcn_kmsg_put);


void pcn_kmsg_done(void *msg)
{
#ifdef CONFIG_POPCORN_CHECK_SANITY
	struct pcn_kmsg_hdr *h = msg;;
	if (atomic_dec_return(__nr_outstanding_requests + h->type) < 0) {
		printk(KERN_ERR "Over-release message type %d\n", h->type);
	}
#endif
	////////////////////////////////////////////////////////////////////////////////////////////////same as above function
	if (transport && transport->done) {
		transport->done(msg);
	} else {
		kfree(msg);
	}
}
EXPORT_SYMBOL(pcn_kmsg_done);


void pcn_kmsg_stat(struct seq_file *seq, void *v)
{
	////////////////////////////////////////////////////////////////////////////////////////////////same as above function, more below not labelled
	if (transport && transport->stat) {
		transport->stat(seq, v);
	}
}
EXPORT_SYMBOL(pcn_kmsg_stat);

bool pcn_kmsg_has_features(unsigned int features)
{
	if (!transport) return false;

	return (transport->features & features) == features;
}
EXPORT_SYMBOL(pcn_kmsg_has_features);


int pcn_kmsg_rdma_read(int from_nid, void *addr, dma_addr_t rdma_addr, size_t size, u32 rdma_key)
{
#ifdef CONFIG_POPCORN_CHECK_SANITY
	if (!transport || !transport->rdma_read) return -EPERM;
#endif

	account_pcn_rdma_read(size);
	return transport->rdma_read(from_nid, addr, rdma_addr, size, rdma_key);
}
EXPORT_SYMBOL(pcn_kmsg_rdma_read);

int pcn_kmsg_rdma_write(int dest_nid, dma_addr_t rdma_addr, void *addr, size_t size, u32 rdma_key)
{
#ifdef CONFIG_POPCORN_CHECK_SANITY
	if (!transport || !transport->rdma_write) return -EPERM;
#endif

	account_pcn_rdma_write(size);
    return transport->rdma_write(dest_nid, rdma_addr, addr, size, rdma_key);
}
EXPORT_SYMBOL(pcn_kmsg_rdma_write);


struct pcn_kmsg_rdma_handle *pcn_kmsg_pin_rdma_buffer(void *buffer, size_t size)
{
	if (transport && transport->pin_rdma_buffer) {
		return transport->pin_rdma_buffer(buffer, size);
	}
	return ERR_PTR(-EINVAL);
}
EXPORT_SYMBOL(pcn_kmsg_pin_rdma_buffer);

void pcn_kmsg_unpin_rdma_buffer(struct pcn_kmsg_rdma_handle *handle)
{
	if (transport && transport->unpin_rdma_buffer) {
		transport->unpin_rdma_buffer(handle);
	}
}
EXPORT_SYMBOL(pcn_kmsg_unpin_rdma_buffer);


void pcn_kmsg_dump(struct pcn_kmsg_message *msg)
{
	struct pcn_kmsg_hdr *h = &msg->header;
	printk("MSG %p: from=%d type=%d size=%lu\n",
			msg, h->from_nid, h->type, h->size);
}
EXPORT_SYMBOL(pcn_kmsg_dump);


int __init pcn_kmsg_init(void)
{
	return 0;
}
