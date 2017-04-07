#ifndef _POPCORN_WAIT_STATION_H_
#define _POPCORN_WAIT_STATION_H_

#include <linux/completion.h>
#include <linux/atomic.h>

struct wait_station {
	int id;
	pid_t pid;
	void *private;
	struct completion pendings;
	atomic_t pendings_count;
};

extern struct wait_station wait_stations[];

struct wait_station *get_wait_station(pid_t pid);
void put_wait_station(pid_t pid, int i);
#endif
