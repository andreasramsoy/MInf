/*
 * internal.h
 *
 * TODO Code refactoring is needed
 * This is just using a doubly linked list protected by a spinlock
 */

#ifndef KERNEL_POPCORN_INTERNAL_H_
#define KERNEL_POPCORN_INTERNAL_H_

#undef USE_DEBUG_MAPPINGS

#include <linux/spinlock.h>
#include <linux/process_server.h>

/* TODO use general spinlock_t instead of spinlock_t */
extern mapping_answers_for_2_kernels_t* _mapping_head;
extern spinlock_t _mapping_head_lock;

extern ack_answers_for_2_kernels_t* _ack_head;
extern spinlock_t _ack_head_lock;

extern struct list_head _count_head;
extern spinlock_t _count_head_lock;

extern struct list_head _memory_head;
extern spinlock_t _memory_head_lock;

extern struct list_head _vma_ack_head;
extern spinlock_t _vma_ack_head_lock;

static inline void push_data(data_header_t** phead, spinlock_t* spinlock,
		data_header_t* entry)
{
	data_header_t* head;
	unsigned long flags;

	if (!entry)
		return;
	entry->prev = NULL;

	spin_lock_irqsave(spinlock, flags);
	head = *phead;

	if (!head) {
		entry->next = NULL;
		*phead = entry;
	} else {
		entry->next = head;
		head->prev = entry;
		*phead = entry;
	}
	spin_unlock_irqrestore(spinlock, flags);
}

static inline data_header_t* pop_data(data_header_t** phead, spinlock_t* spinlock)
{
	data_header_t* ret = NULL;
	data_header_t* head;
	unsigned long flags;

	spin_lock_irqsave(spinlock, flags);
	head = *phead;

	if (head) {
		ret = head;
		if (head->next) {
			head->next->prev = NULL;
		}
		*phead = head->next;
		ret->next = NULL;
		ret->prev = NULL;
	}
	spin_unlock_irqrestore(spinlock, flags);

	return ret;
}

static inline int count_data(data_header_t** phead, spinlock_t* spinlock)
{
	int ret = 0;
	unsigned long flags;
	data_header_t* head;
	data_header_t* curr;

	spin_lock_irqsave(spinlock, flags);
	head = *phead;

	curr = *phead;
	while (curr) {
		ret++;
		curr = curr->next;
	}
	spin_unlock_irqrestore(spinlock, flags);

	return ret;
}


#define CHECK_FOR_DUPLICATES

#if 0 // beowulf
///////////////////////////////////////////////////////////////////////////////
// Specialized functions (TODO need massive refactoring)
///////////////////////////////////////////////////////////////////////////////

/*
 * Functions to manipulate mapping list
 * head: _mapping_head
 * lock: _mapping_head_lock
 */
static inline void add_mapping_entry(mapping_answers_for_2_kernels_t* entry)
{
	mapping_answers_for_2_kernels_t* curr;
	unsigned long flags;

	if (!entry)
		return;

	spin_lock_irqsave(&_mapping_head_lock, flags);

	if (!_mapping_head) {
		_mapping_head = entry;
		entry->next = NULL;
		entry->prev = NULL;
	}
	else {
		curr = _mapping_head;
		while (curr->next != NULL) {
			curr = curr->next;
		}
		// Now curr should be the last entry.
		// Append the new entry to curr.
		curr->next = entry;
		entry->next = NULL;
		entry->prev = curr;
	}

	spin_unlock_irqrestore(&_mapping_head_lock, flags);
#ifdef USE_DEBUG_MAPPINGS
	{
		data_response_for_2_kernels_t *	response = (data_response_for_2_kernels_t*) entry->data;
		printk("%s: INFO: %pS %s pid %d f%dw%d (cpu %d id %d address 0x%lx) 0x%lx\n",
				__func__, __builtin_return_address(0), current->comm, (int)current->pid,
				entry->is_fetch, entry->is_write,
				entry->tgroup_home_cpu, entry->tgroup_home_id, entry->address,
				(unsigned long) response);
	}
#endif
}

static inline mapping_answers_for_2_kernels_t* find_mapping_entry(int cpu, int id, unsigned long address)
{
	mapping_answers_for_2_kernels_t* curr = NULL;
	mapping_answers_for_2_kernels_t* ret = NULL;
	unsigned long flags;

	spin_lock_irqsave(&_mapping_head_lock, flags);

	curr = _mapping_head;
	while (curr) {
		if (curr->tgroup_home_cpu == cpu
				&& curr->tgroup_home_id == id
				&& curr->address == address) {
			ret = curr;
#ifdef CHECK_FOR_DUPLICATES
			curr = curr->next;
			while (curr) {
				if (curr->tgroup_home_cpu == cpu && curr->tgroup_home_id == id
						&& curr->address == address)
					printk(KERN_ERR"%s: ERROR: duplicates in list %s %s (cpu %d id %d address %lx)\n",
							__func__, ret->path, curr->path, cpu, id, address);
				curr = curr->next;
			}
#endif
			break;
		}
		curr = curr->next;
	}

	spin_unlock_irqrestore(&_mapping_head_lock, flags);

	return ret;
}

static inline void remove_mapping_entry(mapping_answers_for_2_kernels_t* entry)
{
	unsigned long flags;

	if (!entry)
		return;

	spin_lock_irqsave(&_mapping_head_lock, flags);

	if (_mapping_head == entry) {
		_mapping_head = entry->next;
	}

	if (entry->next) {
		entry->next->prev = entry->prev;
	}

	if (entry->prev) {
		entry->prev->next = entry->next;
	}

	entry->prev = NULL;
	entry->next = NULL;

	spin_unlock_irqrestore(&_mapping_head_lock, flags);

#ifdef USE_DEBUG_MAPPPINGS
	{
	data_response_for_2_kernels_t *	response = (data_response_for_2_kernels_t*) entry->data;
	printk("%s: INFO: %pS %s pid %d f%dw%d (cpu %d id %d address 0x%lx) 0x%lx\n",
			__func__, __builtin_return_address(0), current->comm, (int)current->pid,
			entry->is_fetch, entry->is_write,
			entry->tgroup_home_cpu, entry->tgroup_home_id, entry->address,
			(unsigned long) response);
	}
#endif
}

/* Functions to add, find and remove an entry from the ack list (head:_ack_head , lock:_ack_head_lock)
 */
static inline void add_ack_entry(ack_answers_for_2_kernels_t* entry)
{
	ack_answers_for_2_kernels_t* curr;
	unsigned long flags;

	if (!entry)
		return;

	spin_lock_irqsave(&_ack_head_lock, flags);

	if (!_ack_head) {
		_ack_head = entry;
		entry->next = NULL;
		entry->prev = NULL;
	}
	else {
		curr = _ack_head;
		while (curr->next != NULL) {
			curr = curr->next;
		}
		// Now curr should be the last entry.
		// Append the new entry to curr.
		curr->next = entry;
		entry->next = NULL;
		entry->prev = curr;
	}

	spin_unlock_irqrestore(&_ack_head_lock, flags);
}

static inline ack_answers_for_2_kernels_t* find_ack_entry(int cpu, int id, unsigned long address)
{
	ack_answers_for_2_kernels_t* curr = NULL;
	ack_answers_for_2_kernels_t* ret = NULL;
	unsigned long flags;

	spin_lock_irqsave(&_ack_head_lock, flags);

	curr = _ack_head;
	while (curr) {
		if (curr->tgroup_home_cpu == cpu && curr->tgroup_home_id == id
				&& curr->address == address) {
			ret = curr;
#ifdef CHECK_FOR_DUPLICATES
			curr = curr->next;
			while (curr) {
				if (curr->tgroup_home_cpu == cpu && curr->tgroup_home_id == id
						&& curr->address == address)
					printk(KERN_ERR"%s: ERROR: duplicates in list %s %s (cpu %d id %d address %lx)\n",
							__func__, ret->waiting ? ret->waiting->comm : "?", curr->waiting ? curr->waiting->comm : "?",
							cpu, id, address);
				curr = curr->next;
			}
#endif
			break;
		}
		curr = curr->next;
	}

	spin_unlock_irqrestore(&_ack_head_lock, flags);
	return ret;
}

static inline void remove_ack_entry(ack_answers_for_2_kernels_t* entry)
{
	unsigned long flags;

	if (!entry) {
		return;
	}

	spin_lock_irqsave(&_ack_head_lock, flags);

	if (_ack_head == entry) {
		_ack_head = entry->next;
	}

	if (entry->next) {
		entry->next->prev = entry->prev;
	}

	if (entry->prev) {
		entry->prev->next = entry->next;
	}

	entry->prev = NULL;
	entry->next = NULL;

	spin_unlock_irqrestore(&_ack_head_lock, flags);
}
#endif


/*
 * Functions to manipulate memory list
 * head: _memory_head
 * lock: _memory_head_lock
 */
static inline void add_memory_entry(memory_t* entry)
{
	unsigned long flags;

	BUG_ON(!entry);

	spin_lock_irqsave(&_memory_head_lock, flags);
	list_add_tail(&entry->list, &_memory_head);
	spin_unlock_irqrestore(&_memory_head_lock, flags);
}

static inline int add_memory_entry_with_check(memory_t* entry)
{
	memory_t *m;
	unsigned long flags;

	BUG_ON(!entry);

	spin_lock_irqsave(&_memory_head_lock, flags);
	list_for_each_entry(m, &_memory_head, list) {
		if ((m->tgroup_home_cpu == entry->tgroup_home_cpu
			  && m->tgroup_home_id == entry->tgroup_home_id)) {
			spin_unlock_irqrestore(&_memory_head_lock, flags);
			return -1;
		}
	}
	list_add_tail(&entry->list, &_memory_head);
	spin_unlock_irqrestore(&_memory_head_lock,flags);

	return 0;
}

static inline memory_t* find_memory_entry(int cpu, int id)
{
	memory_t *m = NULL;
	memory_t *found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&_memory_head_lock, flags);
	list_for_each_entry(m, &_memory_head, list) {
		if (m->tgroup_home_cpu == cpu && m->tgroup_home_id == id) {
#ifdef CHECK_FOR_DUPLICATES
			if (found) {
				printk(KERN_ERR"%s: duplicates in list %s %s (cpu %d id %d)\n",
						__func__, found->path, m->path, cpu, id);
			}
			found = m;
#else
			found = m;
			break;
#endif
		}
	}
	spin_unlock_irqrestore(&_memory_head_lock, flags);

	return found;
}

static inline int dump_memory_entries(memory_t * list[], int num, int *written)
{
	memory_t *m = NULL;
	int i = 0;
	bool more = false;
	unsigned long flags;

	spin_lock_irqsave(&_memory_head_lock,flags);
	list_for_each_entry(m, &_memory_head, list) {
		if (i >= num) {
			more = true;
			break;
		}
		list[i] = m;
		i++;
	}
	spin_unlock_irqrestore(&_memory_head_lock,flags);

	if (written)
		*written = i;

	return more;
}

static inline void remove_memory_entry(memory_t* entry)
{
	unsigned long flags;

	BUG_ON(!entry);

	spin_lock_irqsave(&_memory_head_lock,flags);
	list_del_init(&entry->list);
	spin_unlock_irqrestore(&_memory_head_lock,flags);
}


/*
 * Functions to manipulate count list
 * head: _count_head
 * lock: _count_head_lock
 */
static inline void add_count_entry(count_answers_t *entry)
{
	unsigned long flags;

	BUG_ON(!entry);

	spin_lock_irqsave(&_count_head_lock, flags);
	list_add_tail(&entry->list, &_count_head);
	spin_unlock_irqrestore(&_count_head_lock, flags);
}

static inline count_answers_t* find_count_entry(int cpu, int id)
{
	count_answers_t* e = NULL;
	count_answers_t* found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&_count_head_lock, flags);
	list_for_each_entry(e, &_count_head, list) {
		if (e->tgroup_home_cpu == cpu && e->tgroup_home_id == id) {
#ifdef CHECK_FOR_DUPLICATES
			if (found) {
				printk(KERN_ERR"%s: duplicates in list %s %s (cpu %d id %d)\n",
							__func__, 
							found->waiting ? found->waiting->comm : "?",
							e->waiting ? e->waiting->comm : "?",
							cpu, id);
			}
			found = e;
#else
			found = e;
			break;
#endif
		}
	}
	spin_unlock_irqrestore(&_count_head_lock, flags);

	return found;
}

static inline void remove_count_entry(count_answers_t* entry)
{
	unsigned long flags;

	BUG_ON(!entry);

	spin_lock_irqsave(&_count_head_lock, flags);
	list_del_init(&entry->list);
	spin_unlock_irqrestore(&_count_head_lock, flags);
}


/*
 * Functions to manipulate vma_ack list
 * head: _vma_ack_head
 * lock: _vma_ack_head_lock
 */
static inline void add_vma_ack_entry(vma_op_answers_t* entry)
{
	unsigned long flags;

	if (!entry)
		return;

	spin_lock_irqsave(&_vma_ack_head_lock, flags);
	list_add_tail(&entry->list, &_vma_ack_head);
	spin_unlock_irqrestore(&_vma_ack_head_lock, flags);
}

static inline vma_op_answers_t* find_vma_ack_entry(int cpu, int id)
{
	vma_op_answers_t* v = NULL;
	vma_op_answers_t* found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&_vma_ack_head_lock, flags);
	list_for_each_entry(v, &_vma_ack_head, list) {
		if (v->tgroup_home_cpu == cpu && v->tgroup_home_id == id) {
#ifdef CHECK_FOR_DUPLICATES
			if (found) {
				printk(KERN_ERR"%s: duplicates in list %s %s (cpu %d id %d)\n",
						__func__,
						found->waiting ? found->waiting->comm : "?",
						v->waiting ? v->waiting->comm : "?",
						cpu, id);
			}
			found = v;
#else
			found = v;
			break;
#endif
		}
	}
	spin_unlock_irqrestore(&_vma_ack_head_lock, flags);

	return found;
}

static inline void remove_vma_ack_entry(vma_op_answers_t* entry)
{
	unsigned long flags;

	spin_lock_irqsave(&_vma_ack_head_lock, flags);
	list_del_init(&entry->list);
	spin_unlock_irqrestore(&_vma_ack_head_lock, flags);
}


/*
 KMEM CACHES TO USE
 data = (count_answers_t*) kmalloc(sizeof(count_answers_t), GFP_ATOMIC);
 request= (remote_thread_count_request_t*) kmalloc(sizeof(remote_thread_count_request_t),GFP_ATOMIC);
 new_kernel_work_answer_t* work= (new_kernel_work_answer_t*)kmalloc(sizeof(new_kernel_work_answer_t), GFP_ATOMIC);
 new_kernel_answer_t* answer= (new_kernel_answer_t*) kmalloc(sizeof(new_kernel_answer_t), GFP_ATOMIC);
 request_work = (new_kernel_work_t*) kmalloc(sizeof(new_kernel_work_t), GFP_ATOMIC);
 create_thread_pull_t* msg= (create_thread_pull_t*) kmalloc(sizeof(create_thread_pull_t),GFP_ATOMIC);
 my_thread_pull = (thread_pull_t*) kmalloc(sizeof(thread_pull_t), GFP_ATOMIC);
 shadow_thread_t* shadow = (shadow_thread_t*) kmalloc(sizeof(shadow_thread_t), GFP_ATOMIC);
 struct work_struct* work = kmalloc(sizeof(struct work_struct), GFP_ATOMIC);
 vma_op_work_t* work = kmalloc(sizeof(vma_op_work_t), GFP_ATOMIC);
 response= (ack_t*) kmalloc(sizeof(ack_t), GFP_ATOMIC);
 delay = (invalid_work_t*) kmalloc(sizeof(invalid_work_t), GFP_ATOMIC);
 delay = (request_work_t*)kmalloc(sizeof(request_work_t), GFP_ATOMIC);
 response = (data_response_for_2_kernels_t*) kmalloc(sizeof(data_response_for_2_kernels_t)+PAGE_SIZE, GFP_ATOMIC);
 request_work = kmalloc(sizeof(exit_group_work_t), GFP_ATOMIC);
 request_work = kmalloc(sizeof(exit_work_t), GFP_ATOMIC);
 response= (remote_thread_count_response_t*) kmalloc(sizeof(remote_thread_count_response_t),GFP_ATOMIC);
 request_work = kmalloc(sizeof(count_work_t), GFP_ATOMIC);
 exiting_process_t* msg = (exiting_process_t*) kmalloc(sizeof(exiting_process_t), GFP_ATOMIC);
 msg= (create_process_pairing_t*) kmalloc(sizeof(create_process_pairing_t),GFP_ATOMIC);
 data_request_for_2_kernels_t* read_message = (data_request_for_2_kernels_t*) kmalloc(sizeof(data_request_for_2_kernels_t), GFP_ATOMIC);
 ack_answers_for_2_kernels_t* answers = (ack_answers_for_2_kernels_t*) kmalloc(sizeof(ack_answers_for_2_kernels_t), GFP_ATOMIC);
 invalid_data_for_2_kernels_t* invalid_message = (invalid_data_for_2_kernels_t*) kmalloc(sizeof(invalid_data_for_2_kernels_t), GFP_ATOMIC);
 data_request_for_2_kernels_t* write_message = (data_request_for_2_kernels_t*) kmalloc(sizeof(data_request_for_2_kernels_t),GFP_ATOMIC);
 mapping_answers_for_2_kernels_t* writing_page = (mapping_answers_for_2_kernels_t*) kmalloc(sizeof(mapping_answers_for_2_kernels_t), GFP_ATOMIC);
 fetching_page = (mapping_answers_for_2_kernels_t*) kmalloc(sizeof(mapping_answers_for_2_kernels_t), GFP_ATOMIC);
 fetch_message = (data_request_for_2_kernels_t*) kmalloc(sizeof(data_request_for_2_kernels_t), GFP_ATOMIC);
 request= (back_migration_request_t*) kmalloc(sizeof(back_migration_request_t), GFP_ATOMIC);
 request = kmalloc(sizeof(clone_request_t), GFP_ATOMIC);
 vma_ack_t* ack_to_server = (vma_ack_t*) kmalloc(sizeof(vma_ack_t), GFP_ATOMIC);
 work = kmalloc(sizeof(vma_lock_work_t), GFP_ATOMIC);
 vma_lock_t* lock_message = (vma_lock_t*) kmalloc(sizeof(vma_lock_t), GFP_ATOMIC);
 struct work_struct* work = kmalloc(sizeof(struct work_struct), GFP_ATOMIC);
 clone_work_t* delay = (clone_work_t*) kmalloc(sizeof(clone_work_t), GFP_ATOMIC);
 */


#endif /* KERNEL_POPCORN_INTERNAL_H_ */
