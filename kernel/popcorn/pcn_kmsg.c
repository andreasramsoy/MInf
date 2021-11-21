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
#include <popcorn/node_list.h> //to access the node list

static pcn_kmsg_cbftn pcn_kmsg_cbftns[PCN_KMSG_TYPE_MAX] = { NULL };

static struct pcn_kmsg_transport *transport = NULL;

/**
 * TODO: Remove following function (it should no longer be being used)
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

void pcn_kmsg_process(struct pcn_kmsg_message *msg)
{
	pcn_kmsg_cbftn ftn;


#ifdef POPCORN_ENCRYPTION_ON

	unsigned int ret, i, j, iv_len;
	const char *key;
	char iv[POPCORN_AES_KEY_SIZE];
	struct crypto_blkcipher *tfm;
	struct blkcipher_desc desc;
	u32 *b_size;
	const char *algo;
	unsigned int secs;
	struct cipher_speed_template *template;
	unsigned int tcount;
	u8 *keysize;
	struct message_node* node;
	struct scatterlist ciphertext;
	struct scatterlist plaintext;


	keysize = POPCORN_AES_KEY_SIZE;
	algo = "xts(aes)";

	tfm = crypto_alloc_blkcipher(algo, 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		printk("failed to load transform for %s: %ld\n", algo,
		       PTR_ERR(tfm));
		return;
	}
	desc.tfm = tfm;
	desc.flags = 0;

	/*if (msg->header == NULL) {
		printk(KERN_ERR "Could not decrypt message as it has no header\n");
		goto decryption_fail;
	}*/

	node = get_node(msg->header.from_nid);
	if (!node) {
		printk(KERN_ERR "Could not get node %d to decrypt message\n", msg->header.from_nid);
		goto decryption_fail;
	}

	//set key
	ret = crypto_cipher_setkey(tfm, node->key, POPCORN_AES_KEY_SIZE_BYTES);
	if (ret != 0) {
		printk(KERN_ERR "Failed to set the cipher key, error: %d\n", ret);
		goto decryption_fail;
	}

	//generate an IV
	//iv_len = crypto_blkcipher_ivsize(tfm); //for encryption
	crypto_blkcipher_set_iv(tfm, msg->iv, sizeof(msg->iv));
	

	//perform decryption
	memcpy(&ciphertext, msg->payload, sizeof(msg->payload));
	ret = crypto_blkcipher_decrypt(tfm, &plaintext, &ciphertext, sizeof(ciphertext));
	if (ret != 0) {
		printk(KERN_ERR "Failed to decrypt, error: %d\n", ret);
	}
	memcpy(msg->payload, &plaintext, sizeof(plaintext));

	//message has now been replaced with plaintext version of message 


	/*if ((*keysize + *b_size) > TVMEMSIZE * PAGE_SIZE) {
		printk("template (%u) too big for "
				"tvmem (%lu)\n", *keysize + *b_size,
				TVMEMSIZE * PAGE_SIZE);
		goto decryption_fail;
	}

	printk("test %u (%d bit key, %d byte blocks): ", i,
			*keysize * 8, *b_size);

	memset(tvmem[0], 0xff, PAGE_SIZE);

	//set key, plain text and IV
	key = tvmem[0];
	for (j = 0; j < tcount; j++) {
		if (template[j].klen == *keysize) {
			key = template[j].key;
			break;
		}
	}

	ret = crypto_blkcipher_setkey(tfm, key, *keysize);
	if (ret) {
		printk("setkey() failed flags=%x\n",
				crypto_blkcipher_get_flags(tfm));
		goto decryption_fail;
	}

	sg_init_table(sg, TVMEMSIZE);
	sg_set_buf(sg, tvmem[0] + *keysize,
			PAGE_SIZE - *keysize);
	for (j = 1; j < TVMEMSIZE; j++) {
		sg_set_buf(sg + j, tvmem[j], PAGE_SIZE);
		memset (tvmem[j], 0xff, PAGE_SIZE);
	}

	iv_len = crypto_blkcipher_ivsize(tfm);
	if (iv_len) {
		memset(&iv, 0xff, iv_len);
		crypto_blkcipher_set_iv(tfm, iv, iv_len);
	}

	if (secs)
		ret = test_cipher_jiffies(&desc, "decryption", sg,
						*b_size, secs);
	else
		ret = test_cipher_cycles(&desc, "decryption", sg,
						*b_size);

	if (ret) {
		printk("%s() failed flags=%x\n", e, desc.flags);
		break;
	}*/

	/* //wrong kernel version encryption
	int error;
	struct scatterlist sg;
	struct crypto_wait wait;
	struct message_node* node;
	
	if (!(msg->header)) {
		printk(KERN_ERR "Message does not have a header (cannot get sender)\n");
		goto decryption_fail;
	}
	node = get_node(msg->header.from_nid);

    DECLARE_CRYPTO_WAIT(wait);
	if (node == NULL) {
		printk(KERN_ERR "The message could not be encrypted as it was sent from node %d which does not exist\n", msg->header.from_nid);
		goto decryption_fail;
	}
	
	//the input here is only from kernel modules so shouldn't be vulnerable to injection so safe to use sizeof
	sg_init_one(&sg, msg->payload, sizeof(msg->payload));
	skcipher_request_set_callback(node->cipher_request, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
	skcipher_request_set_crypt(node->cipher_request, &sg, &sg, sizeof(struct pcn_kmsg_message), msg->iv);
	error = crypto_wait_req(crypto_skcipher_decrypt(node->cipher_request), &wait);
	if (error) {
			printk(KERN_ERR "Error decrypting data: %d, from node %d\n", error, msg->header.from_nid);
			goto decryption_fail;
	}

	//now ready to process msg as normal
	*/
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
	crypto_free_blkcipher(tfm);
	pcn_kmsg_done(msg);
	#endif
}
EXPORT_SYMBOL(pcn_kmsg_process);


static inline int __build_and_check_msg(enum pcn_kmsg_type type, int to, struct pcn_kmsg_message* msg, size_t size)
{
#ifdef CONFIG_POPCORN_CHECK_SANITY
	BUG_ON(type < 0 || type >= PCN_KMSG_TYPE_MAX);
	BUG_ON(size > PCN_KMSG_MAX_SIZE);
	BUG_ON(to < 0 || to >= MAX_POPCORN_NODES);
	BUG_ON(to == my_nid);
#endif

	int error;
	struct scatterlist sg;
	//struct crypto_wait wait;
	struct message_node* node = get_node(to);

	msg->header.type = type;
	msg->header.prio = PCN_KMSG_PRIO_NORMAL;
	msg->header.size = size;
	msg->header.from_nid = my_nid;


#ifdef POPCORN_ENCRYPTION_ON


	unsigned int ret, i, j, iv_len;
	const char *key;
	char iv[POPCORN_AES_KEY_SIZE];
	struct crypto_blkcipher *tfm;
	struct blkcipher_desc desc;
	u32 *b_size;
	const char *algo;
	unsigned int secs;
	struct cipher_speed_template *template;
	unsigned int tcount;
	u8 *keysize;
	struct message_node* node;
	struct scatterlist ciphertext;
	struct scatterlist plaintext;


	keysize = POPCORN_AES_KEY_SIZE;
	algo = "xts(aes)";

	tfm = crypto_alloc_blkcipher(algo, 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		printk("failed to load transform for %s: %ld\n", algo,
		       PTR_ERR(tfm));
		return;
	}
	desc.tfm = tfm;
	desc.flags = 0;

	/*if (msg->header == NULL) {
		printk(KERN_ERR "Could not encrypt message as it has no header\n");
		goto encryption_fail;
	}*/

	node = get_node(msg->header.from_nid);
	if (!node) {
		printk(KERN_ERR "Could not get node %d to encrypt message\n", msg->header.from_nid);
		goto encryption_fail;
	}

	//set key
	ret = crypto_cipher_setkey(tfm, node->key, POPCORN_AES_KEY_SIZE_BYTES);
	if (ret != 0) {
		printk(KERN_ERR "Failed to set the cipher key, error: %d\n", ret);
		goto encryption_fail;
	}

	//generate an IV
	//iv_len = crypto_blkcipher_ivsize(tfm); //for encryption
	crypto_blkcipher_set_iv(tfm, msg->iv, sizeof(msg->iv));
	

	//perform encryption
	memcpy(&plaintext, msg->payload, sizeof(msg->payload));
	ret = crypto_blkcipher_encrypt(tfm, &ciphertext, &plaintext, sizeof(plaintext));
	if (ret != 0) {
		printk(KERN_ERR "Failed to encrypt, error: %d\n", ret);
		goto encryption_fail;
	}
	memcpy(msg->payload, &ciphertext, sizeof(plaintext));

	//message has now been replaced with ciphertext version of message 

	/*
	//wrong encrption for kernel version
    DECLARE_CRYPTO_WAIT(wait);

	if (get_node(to) == NULL) {
		printk(KERN_ERR "Trying to build message for node that does not exist\n");
		goto encryption_fail;
	}

	get_random_bytes(msg->iv, POPCORN_AES_IV_LENGTH); //fill with random bytes for each message

	//encrypt the message (setup is done on node initialisation, enable_node function, to save time)
	sg_init_one(&sg, msg->payload, POPCORN_AES_IV_LENGTH);
	skcipher_request_set_callback(node->cipher_request, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
	skcipher_request_set_crypt(node->cipher_request, &sg, &sg, sizeof(msg->payload), msg->iv);
	error = crypto_wait_req(crypto_skcipher_decrypt(node->cipher_request), &wait);
	if (error) {
			printk(KERN_ERR "Error decrypting data: %d, from node %d\n", error, msg->header.from_nid);
			goto encryption_fail;
	}

	//now ready to send message the message as normal
	//message is now encrypted
	*/
#endif

	return 0;

encryption_fail:
	crypto_free_blkcipher(tfm);
	printk(KERN_ERR "Error encrypting, abort message!\n");
	return 1;
}

int pcn_kmsg_send(enum pcn_kmsg_type type, int to, void *msg, size_t size)
{
	int ret;
	if ((ret = __build_and_check_msg(type, to, msg, size))) return ret;

	account_pcn_message_sent(msg);
	
	/*if (to == my_nid) {
		printk(KERN_ERR "Sending a message to myself, transport does not exist - skip layer\n");
		printk(KERN_ERR "Message type: %d, to: %d", type, to);
		return 1;
	}*/
	/*printk(KERN_DEBUG "Sending to: %d", to);
	printk(KERN_DEBUG "Node address: %p", get_node(to));
	printk(KERN_DEBUG "Node address: %p", get_node(to)->transport);
	printk(KERN_DEBUG "Node address: %p", get_node(to)->transport->send);*/
	
	return get_node(to)->transport->send(to, msg, size);
}
EXPORT_SYMBOL(pcn_kmsg_send);

int pcn_kmsg_post(enum pcn_kmsg_type type, int to, void *msg, size_t size)
{
	int ret;
	if ((ret = __build_and_check_msg(type, to, msg, size))) return ret;

	account_pcn_message_sent(msg);
	/*printk(KERN_DEBUG "PCN_KMSG_POST!\n");
	if (to == my_nid) {
		printk(KERN_ERR "Should never post message to yourself! Abort message.\n");
		return 1;
	}*/
	
	return get_node(to)->transport->post(to, msg, size);
}
EXPORT_SYMBOL(pcn_kmsg_post);

void *pcn_kmsg_get(size_t size)
{

	if (transport && transport->get)
		return transport->get(size);
	
	return kmalloc(size, GFP_KERNEL);
}
EXPORT_SYMBOL(pcn_kmsg_get);

void pcn_kmsg_put(void *msg)
{
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
	if (get_node(find_first_null_pointer())) {
		get_node(find_first_null_pointer())->transport->done(msg);
	} else {
		kfree(msg);
	}
}
EXPORT_SYMBOL(pcn_kmsg_done);


void pcn_kmsg_stat(struct seq_file *seq, void *v)
{
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
