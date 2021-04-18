#include <asm/bug.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>

#include <popcorn/pcn_kmsg.h>
#include <popcorn/bundle.h>
#include <popcorn/debug.h>
#include <popcorn/node_list.h>
#include <popcorn/kmesg_types.h>

/*struct popcorn_node {
	enum popcorn_arch arch;
	int bundle_id;

	bool is_connected;
};*/


//static struct popcorn_node popcorn_nodes[MAX_POPCORN_NODES];

bool get_popcorn_node_online(int nid)
{
	struct message_node* node = get_node(nid);
	if (node) return node->is_connected;
	else {
		printk(KERN_DEBUG "Node %d as it does not exist, so is offline", nid);
		return false;
	}
}
EXPORT_SYMBOL(get_popcorn_node_online);

void set_popcorn_node_online(int nid, bool online)
{
	struct message_node* node = get_node(nid);
	if (node) node->is_connected = online;
	else {
		printk(KERN_ERR "Cannot set online status of node %d as it does not exist", nid);
	}
}
EXPORT_SYMBOL(set_popcorn_node_online);


int my_nid __read_mostly = -1;
EXPORT_SYMBOL(my_nid);

const enum popcorn_arch my_arch =
#ifdef CONFIG_X86_64
	POPCORN_ARCH_X86;
#elif defined(CONFIG_ARM64)
	POPCORN_ARCH_ARM;
#elif defined(CONFIG_PPC64)
	POPCORN_ARCH_PPC;
#else
	POPCORN_ARCH_UNKNOWN;
#endif
EXPORT_SYMBOL(my_arch);

int get_popcorn_node_arch(int nid)
{
	struct message_node* node = get_node(nid);
	if (node) return node->arch;
	else {
		printk(KERN_ERR "Node %d arch requested but it is not in the node list", nid);
	}
	return POPCORN_ARCH_UNKNOWN;
}
EXPORT_SYMBOL(get_popcorn_node_arch);

const char *archs_sz[] = {
	"aarch64",
	"x86_64",
	"ppc64le",
};


//replaced by function that follows 
/** TODO: check it works then delete this code */
/*void broadcast_my_node_info(int nr_nodes)
{
	int i;
	node_info_t info = {
		.nid = my_nid,
		.arch = my_arch,
	};
	for (i = 0; i < nr_nodes; i++) {
		if (i == my_nid) continue;
		pcn_kmsg_send(PCN_KMSG_TYPE_NODE_INFO, i, &info, sizeof(info));
	}
}
EXPORT_SYMBOL(broadcast_my_node_info);*/

//this function does the same as above but just sends info to that particular node
void broadcast_my_node_info_to_node(int nid)
{
	node_info_t info = {
		.nid = my_nid,
		.arch = my_arch,
	};
	printk("Broadcasting my nid (%d) to node %d", my_nid, nid);
	if (my_nid != nid) pcn_kmsg_send(PCN_KMSG_TYPE_NODE_INFO, nid, &info, sizeof(info)); //don't send to yourself!
}
EXPORT_SYMBOL(broadcast_my_node_info_to_node);

static bool my_node_info_printed = false;

static int handle_node_info(struct pcn_kmsg_message *msg)
{
	node_info_t *info = (node_info_t *)msg;
	struct message_node* me = get_node(my_nid);
	struct message_node* them = get_node(info->nid);

	if (my_nid != -1 && !my_node_info_printed && me) {
		me->arch = my_arch;
		my_node_info_printed = true;
	}

	PCNPRINTK("   %d joined, %s\n", info->nid, archs_sz[info->arch]);

	if (them) them->arch = info->arch;
	else printk(KERN_DEBUG "Bundle: Could not set arch of requested node as it does not exist");
	smp_mb();

	pcn_kmsg_done(msg);
	return 0;
}

int __init popcorn_nodes_init(void)
{
	//int i;
	BUG_ON(my_arch == POPCORN_ARCH_UNKNOWN);

	/*for (i = 0; i < MAX_POPCORN_NODES; i++) {
		struct popcorn_node *pn = popcorn_nodes + i;

		pn->is_connected = false;
		pn->arch = POPCORN_ARCH_UNKNOWN;
		pn->bundle_id = -1;
	}*/

	REGISTER_KMSG_HANDLER(PCN_KMSG_TYPE_NODE_INFO, node_info);

	return 0;
}
