/**
 * msg_socket.c
 *  Messaging transport layer over TCP/IP
 *
 * Authors:
 *  Ho-Ren (Jack) Chuang <horenc@vt.edu>
 *  Sang-Hoon Kim <sanghoon@vt.edu>
 */
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include <popcorn/stat.h>
#include "ring_buffer.h"
#include "node_controller.h"
#define PORT 30467
#define MAX_SEND_DEPTH	1024
#define NIPQUAD(addr) ((unsigned char *)&addr)[0],((unsigned char *)&addr)[1],((unsigned char *)&addr)[2],((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

enum {
	SEND_FLAG_POSTED = 0,
};

static int __init init_sock(void);
static void __exit exit_sock(void);
bool init_node_sock(struct message_node* node);



static struct socket *sock_listen = NULL;
static struct ring_buffer send_buffer = {};


/**
 * Handle inbound messages
 */
static int ksock_recv(struct socket *sock, char *buf, size_t len)
{
	struct msghdr msg = {
		.msg_flags = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_name = NULL,
		.msg_namelen = 0,
	};
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = len,
	};

	return kernel_recvmsg(sock, &msg, &iov, 1, len, MSG_WAITALL);
}

static int recv_handler(void* arg0)
{
	struct sock_handle *sh = arg0;
	MSGPRINTK("RECV handler for %d is ready\n", sh->nid);

	while (!kthread_should_stop()) {
		int len;
		int ret;
		size_t offset;
		struct pcn_kmsg_hdr header;
		char *data;

		/* compose header */
		offset = 0;
		len = sizeof(header);
		while (len > 0) {
			ret = ksock_recv(sh->sock, (char *)(&header) + offset, len);
			if (ret == -1) break;
			offset += ret;
			len -= ret;
		}
		if (ret < 0) break;

#ifdef CONFIG_POPCORN_CHECK_SANITY
		BUG_ON(header.type < 0 || header.type >= PCN_KMSG_TYPE_MAX);
		BUG_ON(header.size < 0 || header.size >  PCN_KMSG_MAX_SIZE);
#endif

		/* compose body */
		data = kmalloc(header.size, GFP_KERNEL);
		BUG_ON(!data && "Unable to alloc a message");

		memcpy(data, &header, sizeof(header));

		offset = sizeof(header);
		len = header.size - offset;

		while (len > 0) {
			ret = ksock_recv(sh->sock, data + offset, len);
			if (ret == -1) break;
			offset += ret;
			len -= ret;
		}
		if (ret < 0) break;

		/* Call pcn_kmsg upper layer */
		pcn_kmsg_process((struct pcn_kmsg_message *)data);
	}
	return 0;
}


/**
 * Handle outbound messages
 */
static int ksock_send(struct socket *sock, char *buf, size_t len)
{
	struct msghdr msg = {
		.msg_flags = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_name = NULL,
		.msg_namelen = 0,
	};
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = len,
	};

	return kernel_sendmsg(sock, &msg, &iov, 1, len);
}

static int enq_send(int dest_nid, struct pcn_kmsg_message *msg, unsigned long flags, struct completion *done)
{
	int ret;
	unsigned long at;
	struct sock_handle *sh = get_node(dest_nid)->handle;
	struct q_item *qi;
	do {
		ret = down_interruptible(&sh->q_full);
	} while (ret);

	spin_lock(&sh->q_lock);
	at = sh->q_tail;
	qi = sh->msg_q + at;
	sh->q_tail = (at + 1) & (MAX_SEND_DEPTH - 1);

	qi->msg = msg;
	qi->flags = flags;
	qi->done = done;
	spin_unlock(&sh->q_lock);
	up(&sh->q_empty);

	return at;
}

void sock_kmsg_put(struct pcn_kmsg_message *msg);

static int deq_send(struct sock_handle *sh)
{
	int ret;
	char *p;
	unsigned long from;
	size_t remaining;
	struct pcn_kmsg_message *msg;
	struct q_item *qi;
	unsigned long flags;
	struct completion *done;

	do {
		ret = down_interruptible(&sh->q_empty);
	} while (ret);

	spin_lock(&sh->q_lock);
	from = sh->q_head;
	qi = sh->msg_q + from;
	sh->q_head = (from + 1) & (MAX_SEND_DEPTH - 1);

	msg = qi->msg;
	flags = qi->flags;
	done = qi->done;
	spin_unlock(&sh->q_lock);
	up(&sh->q_full);

	p = (char *)msg;
	remaining = msg->header.size;

	while (remaining > 0) {
		int sent = ksock_send(sh->sock, p, remaining);
		if (sent < 0) {
			MSGPRINTK("send interrupted, %d\n", sent);
			io_schedule();
			continue;
		}
		p += sent;
		remaining -= sent;
		//printk("Sent %d remaining %d\n", sent, remaining);
	}
	if (test_bit(SEND_FLAG_POSTED, &flags)) {
		sock_kmsg_put(msg);
	}
	if (done) complete(done);

	return 0;
}

static int send_handler(void* arg0)
{
	struct sock_handle *sh = arg0;
	MSGPRINTK("SEND handler for %d is ready\n", sh->nid);

	while (!kthread_should_stop()) {
		deq_send(sh);
	}
	kfree(sh->msg_q);
	return 0;
}


#define WORKAROUND_POOL
/***********************************************
 * Manage send buffer
 ***********************************************/
struct pcn_kmsg_message *sock_kmsg_get(size_t size)
{
	struct pcn_kmsg_message *msg;
	might_sleep();

#ifdef WORKAROUND_POOL
	msg = kmalloc(size, GFP_KERNEL);
#else
	while (!(msg = ring_buffer_get(&send_buffer, size))) {
		WARN_ON_ONCE("ring buffer is full\n");
		schedule();
	}
#endif
	return msg;
}

void sock_kmsg_put(struct pcn_kmsg_message *msg)
{
#ifdef WORKAROUND_POOL
	kfree(msg);
#else
	ring_buffer_put(&send_buffer, msg);
#endif
}


/***********************************************
 * This is the interface for message layer
 ***********************************************/
int sock_kmsg_send(int dest_nid, struct pcn_kmsg_message *msg, size_t size)
{
	DECLARE_COMPLETION_ONSTACK(done);
	enq_send(dest_nid, msg, 0, &done);

	if (!try_wait_for_completion(&done)) { 
		int ret = wait_for_completion_io_timeout(&done, 60 * HZ); /////uses spinlock here, are send and post in same queue? Want to prevent blocking
		if (!ret) return -EAGAIN;
	}
	return 0;
}

int sock_kmsg_post(int dest_nid, struct pcn_kmsg_message *msg, size_t size)
{
	enq_send(dest_nid, msg, 1 << SEND_FLAG_POSTED, NULL);
	return 0;
}

void sock_kmsg_done(struct pcn_kmsg_message *msg)
{
	kfree(msg);
}

void sock_kmsg_stat(struct seq_file *seq, void *v)
{
	if (seq) {
		seq_printf(seq, POPCORN_STAT_FMT,
				(unsigned long long)ring_buffer_usage(&send_buffer),
#ifdef CONFIG_POPCORN_STAT
				(unsigned long long)send_buffer.peak_usage,
#else
				0ULL,
#endif
                                "socket");
	}
}


static int __show_peers(struct seq_file *seq, void *v)
{	
	int i;
	char* myself = " ";	
	for (i = 0; i < after_last_node_index; i++) 
	{
		if (i == my_nid) myself = "*";
		seq_printf(seq, "%s %3d  "NIPQUAD_FMT"  %s\n", myself,
		           i, NIPQUAD(get_node(i)->address), "NODE_IP");
		myself = " ";
	}
	return 0;
}


static int __open_peers(struct inode *inode, struct file *file)
{
        return single_open(file, &__show_peers, NULL);
}



static struct file_operations peers_ops = {
        .owner = THIS_MODULE,
        .open = __open_peers,
        .read = seq_read,
        .llseek  = seq_lseek,
        .release = single_release,
};
static struct proc_dir_entry *proc_entry = NULL;
static int peers_init(void)
{
	proc_entry = proc_create("popcorn_peers",  0444, NULL, &peers_ops);
        if (proc_entry == NULL) {
                printk(KERN_ERR"cannot create proc_fs entry for popcorn stats\n");
                return -ENOMEM;
        }
        return 0;
}

static struct task_struct * __init __sock_start_handler(struct message_node* node, const char *type, int (*handler)(void *data))
{
	char name[40];
	struct task_struct *tsk;

	sprintf(name, "pcn_%s_%lld", type, node->index);
	tsk = kthread_run(handler, node->handle, name);
	if (IS_ERR(tsk)) {
		printk(KERN_ERR "Cannot create %s handler, %ld\n", name, PTR_ERR(tsk));
		return tsk;
	}

	/* TODO: support prioritized msg handler
	struct sched_param param = {
		sched_priority = 10};
	};
	sched_setscheduler(tsk, SCHED_FIFO, &param);
	set_cpus_allowed_ptr(tsk, cpumask_of(i%NR_CPUS));
	*/
	return tsk;
}

static int __sock_start_handlers(struct message_node* node)
{
	struct task_struct *tsk_send, *tsk_recv;
	tsk_send = __sock_start_handler(node, "send", send_handler);
	if (IS_ERR(tsk_send)) {
		return PTR_ERR(tsk_send);
	}

	tsk_recv = __sock_start_handler(node, "recv", recv_handler);
	if (IS_ERR(tsk_recv)) {
		kthread_stop(tsk_send);
		return PTR_ERR(tsk_recv);
	}
	node->handle->send_handler = tsk_send;
	node->handle->recv_handler = tsk_recv;
	return 0;
}

static int __init __sock_connect_to_server(struct message_node* node)
{
	int ret;
	struct sockaddr_in addr;
	struct socket *sock;

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (ret < 0) {
		MSGPRINTK("Failed to create socket, %d\n", ret);
		return ret;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = node->address;

	MSGPRINTK("Connecting to %pI4\n", node->address);
	do {
		ret = kernel_connect(sock, (struct sockaddr *)&addr, sizeof(addr), 0);
		if (ret < 0) {
			MSGPRINTK("Failed to connect the socket %d. Attempt again!!\n", ret);
			msleep(1000);
		}
	} while (ret < 0);

	node->handle->sock = sock;
	ret = __sock_start_handlers(node);

	if (ret) return ret;

	return 0;
}

static int __init __sock_accept_client(struct message_node* node)
{
	int i;
	int ret;
	int retry = 0;
	bool found = false;
	struct socket *sock;
	struct sockaddr_in addr;
	int addr_len = sizeof(addr);

	do {
		ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
		if (ret < 0) {
			MSGPRINTK("Failed to create socket, %d\n", ret);
			return ret;
		}

		ret = kernel_accept(sock_listen, &sock, 0);
		if (ret < 0) {
			MSGPRINTK("Failed to accept, %d\n", ret);
			goto out_release;
		}

		ret = kernel_getpeername(sock, (struct sockaddr *)&addr, &addr_len);
		if (ret < 0) {
			goto out_release;
		}

		/* Identify incoming peer nid */
		for (i = 0; i < after_last_node_index; i++) {
			if (addr.sin_addr.s_addr == node->address) {
				found = true;
			}
		}
		if (!found) {
			sock_release(sock);
			continue;
		}
	} while (retry++ < 10 && !found);

	if (!found) return -EAGAIN;
	node->handle->sock = sock;

	ret = __sock_start_handlers(node);
	if (ret) goto out_release;

	return 0;

out_release:
	sock_release(sock);
	return ret;
}

static int __init __sock_listen_to_connection(void)
{
	int ret;
	struct sockaddr_in addr;

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock_listen);
	if (ret < 0) {
		printk(KERN_ERR "Failed to create socket, %d", ret);
		return ret;
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(PORT);

	ret = kernel_bind(sock_listen, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		printk(KERN_ERR "Failed to bind socket, %d\n", ret);
		goto out_release;
	}

	ret = kernel_listen(sock_listen, after_last_node_index);
	if (ret < 0) {
		printk(KERN_ERR "Failed to listen to connections, %d\n", ret);
		goto out_release;
	}

	MSGPRINTK("Ready to accept incoming connections\n");
	return 0;

out_release:
	sock_release(sock_listen);
	sock_listen = NULL;
	return ret;
}

/**
 * Function to stop and remove an individual node
 * @param struct message_node* node to be removed
 */
bool kill_node_sock(struct message_node* node) {
	struct sock_handle* sh;
	sh = node->handle;
	if (sh->send_handler) {
		kthread_stop(sh->send_handler);
	} else {
		if (sh->msg_q) kfree(sh->msg_q);
	}
	if (sh->recv_handler) {
		kthread_stop(sh->recv_handler);
	}
	if (sh->sock) {
		sock_release(sh->sock);
	}
	return true;
}

extern struct pcn_kmsg_transport transport_socket = {
	.name = "socket",
	.features = 0,

	.is_initialised = false,
	.number_of_users = 0,
	.init_transport = init_sock,
	.exit_transport = exit_sock,
	.init_node = init_node_sock,
	.kill_node = kill_node_sock,
	.connect = __sock_connect_to_server,
	.accept = __sock_accept_client

	.get = sock_kmsg_get,
	.put = sock_kmsg_put,
	.stat = sock_kmsg_stat,

	.send = sock_kmsg_send,
	.post = sock_kmsg_post,
	.done = sock_kmsg_done,
};

/**
 * Function to start communications with a node
 * @param struct message_node* node to be added
 */
bool init_node_sock(struct message_node* node) {
	struct sock_handle* sh;
	if (node != NULL) {
		node->transport = &transport_socket; //change from the initial nothing transport structure

		sh = node->handle;

		sh->msg_q = kmalloc(sizeof(*sh->msg_q) * MAX_SEND_DEPTH, GFP_KERNEL);
		if (!sh->msg_q) {
			printk(KERN_ERR "There was not enough memory for the message node struct for the new node to be created\n");
			return false;
		}

		sh->nid = node->index;
		sh->q_head = 0;
		sh->q_tail = 0;
		spin_lock_init(&sh->q_lock);

		sema_init(&sh->q_empty, 0);
		sema_init(&sh->q_full, MAX_SEND_DEPTH);

		if (node->index > my_nid) {
			//you are earlier in the list so you start the connection
			if (__sock_connect_to_server(node)) {
				set_popcorn_node_online(node->index, true); /////////////////////////////////////////////////this should be in the main .c file
				return true;
			}
		}
		else if (node->index < my_nid) {
			if (__sock_accept_client(node)) {
				set_popcorn_node_online(node->index, true); /////////////////////////////////////////////////this should be in the main .c file
				return true;
			}
		}
		else {
			set_popcorn_node_online(node->index, true); /////////////////////////////////////////////////this should be in the main .c file
			return true;
		}
		set_popcorn_node_online(node->index, false); /////////////////////////////////////////////////this should be in the main .c file

	}
	return false;
}

static void __exit exit_sock(void)
{
	transport_socket.is_initialised = false;
	proc_remove(proc_entry);

	if (sock_listen) sock_release(sock_listen);

	ring_buffer_destroy(&send_buffer);

	MSGPRINTK("Successfully unloaded module!\n");
}

static int __init init_sock(void)
{
	int ret;
	MSGPRINTK("Loading Popcorn messaging layer over TCP/IP...\n");

	initialise_node_list();

	my_nid = 0; //initialises to zero so popcorn can boot even if there is no node list
	if (!identify_myself()) return -EINVAL; //sets the my_nid /////////////////////////////////////////////
	pcn_kmsg_set_transport(&transport_socket); //////////////////////////////////////not needed any more because each node is independent

	if ((ret = ring_buffer_init(&send_buffer, "sock_send"))) goto out_exit;

	if ((ret = __sock_listen_to_connection())) return ret;

	/* Wait for a while so that nodes are ready to listen to connections */
	msleep(100);
	
	broadcast_my_node_info(my_nid); ////////////////////////////////////////////////

	PCNPRINTK("Ready on TCP/IP\n");
	peers_init();
	
	transport_socket.is_initialised = true;
	
	return 0;

out_exit:
	exit_sock();
	return ret;
}
