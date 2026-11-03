/* SPDX-License-Identifier: GPL-2.0
 *
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>
 */
#ifndef _FS_FUSE_DEV_I_H
#define _FS_FUSE_DEV_I_H

#include <linux/fuse.h>
#include <linux/types.h>
#include <linux/refcount.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/fs.h>

/* Request IDs stay even */
#define FUSE_REQ_ID_STEP (1ULL << 1)

struct fuse_arg;
struct fuse_args;
struct fuse_pqueue;

/**
 * enum fuse_req_flag - Request flags
 *
 * @FR_FORCE:		force sending of the request even if interrupted
 * @FR_BACKGROUND:	request is sent in the background
 * @FR_WAITING:		request is counted as "waiting"
 * @FR_PENDING:		request is not yet in userspace
 * @FR_SENT:		request is in userspace, waiting for an answer
 * @FR_FINISHED:	request is finished
 * @FR_ASYNC:		request is asynchronous
 * @FR_URING:		request is on a ring queue
 */
enum fuse_req_flag {
	FR_FORCE,
	FR_BACKGROUND,
	FR_WAITING,
	FR_PENDING,
	FR_SENT,
	FR_FINISHED,
	FR_ASYNC,
	FR_URING,
};

/**
 * struct fuse_req - A request to the client
 */
struct fuse_req {
	/** @list: This can be on either the pending or processing lists of a queue */
	struct list_head list;

	/** @args: Input/output arguments */
	struct fuse_args *args;

	/** @count: refcount */
	refcount_t count;

	/** @flags: Request flags, updated with test/set/clear_bit() */
	unsigned long flags;

	/** @in: The request input header */
	struct {
		/** @in.h: The request input header */
		struct fuse_in_header h;
	} in;

	/** @out: The request output header */
	struct {
		/** @out.h: The request output header */
		struct fuse_out_header h;
	} out;

	/** @waitq: Used to wake up the task waiting for completion of request */
	wait_queue_head_t waitq;

	/** @chan: fuse_chan this request belongs to */
	struct fuse_chan *chan;

	void *ring_entry;
	void *ring_queue;
};

struct fuse_chan {
	/** Lock protecting:
	    - connected
	    - ring
	    - ring->queues[qid]
	 */
	spinlock_t lock;

	/* back pointer: fc->chan->conn == fc */
	struct fuse_conn *conn;

	/** The last request id handed out */
	atomic64_t reqctr;

	/** Maximum number of outstanding background requests */
	unsigned max_background;

	/** Number of requests currently in the background */
	unsigned num_background;

	/** Number of background requests currently queued for userspace */
	unsigned active_background;

	/** Protects: max_background, num_background, active_background, blocked */
	spinlock_t bg_lock;

	/** Flag indicating if there are too many outstanding background requests */
	int blocked;

	/** waitq for blocked connection */
	wait_queue_head_t blocked_waitq;

	/** Connection established, cleared on umount, connection
	    abort and device release */
	unsigned connected;

	/** The number of requests waiting for completion */
	atomic_t num_waiting;

	/**  uring connection information*/
	struct fuse_ring *ring;
};

#define FUSE_PQ_HASH_BITS 8
#define FUSE_PQ_HASH_SIZE (1 << FUSE_PQ_HASH_BITS)

struct fuse_pqueue {
	/** Hash table of requests being processed */
	struct list_head *processing;
};

/**
 * struct fuse_dev - Fuse device instance
 */
struct fuse_dev {
	/** @ref: Reference count of this object */
	refcount_t ref;

	/** @sync_init: Issue FUSE_INIT synchronously */
	bool sync_init;

	/** @chan: Fuse channel for this device */
	struct fuse_chan *chan;
};

struct fuse_copy_state {
	struct fuse_req *req;
	struct iov_iter *iter;
	struct page *pg;
	unsigned int len;
	unsigned int offset;
	bool write:1;
	/* set when the payload is zero-copied. folios are filled in place */
	bool skip_folio_copy:1;
	struct {
		unsigned int copied_sz; /* copied size into the user buffer */
	} ring;
};

/* fud->chan gets assigned to this value when /dev/fuse is closed */
#define FUSE_DEV_CHAN_DISCONNECTED ((struct fuse_chan *) 1)

/*
 * Lockless access is OK, because fud->chan is set once during mount and is valid
 * until the file is released.
 *
 * fud->chan is set to FUSE_DEV_CHAN_DISCONNECTED only after the containing file is
 * released, so result is safe to dereference in most cases.  The exception is
 * fuse_dev_is_installed().
 */
static inline struct fuse_chan *fuse_dev_chan_get(struct fuse_dev *fud)
{
	/* Pairs with cmpxchg() in fuse_dev_install() */
	return smp_load_acquire(&fud->chan);
}

static inline struct fuse_dev *fuse_file_to_fud(struct file *file)
{
	return file->private_data;
}

static inline struct fuse_dev *__fuse_get_dev(struct file *file)
{
	struct fuse_dev *fud = fuse_file_to_fud(file);

	if (!fuse_dev_chan_get(fud))
		return NULL;

	return fud;
}

struct fuse_dev *fuse_get_dev(struct file *file);

unsigned int fuse_req_hash(u64 unique);
struct fuse_req *fuse_request_find(struct fuse_pqueue *fpq, u64 unique);

void fuse_dev_end_requests(struct list_head *head);
void fuse_request_bg_finish(struct fuse_chan *fch, struct fuse_req *req);

void fuse_copy_init(struct fuse_copy_state *cs, bool write,
		    struct iov_iter *iter);
/*
 * Return the number of bytes in an arguments list
 */
unsigned int fuse_len_args(unsigned int numargs, struct fuse_arg *args);

int fuse_copy_args(struct fuse_copy_state *cs, unsigned int numargs,
		   unsigned int argpages, struct fuse_arg *args);
int fuse_copy_out_args(struct fuse_copy_state *cs, struct fuse_args *args,
		       unsigned int nbytes);
bool fuse_remove_pending_req(struct fuse_req *req, spinlock_t *lock);

/*
 * Assign a unique id to a fuse request
 */
void fuse_request_assign_unique(struct fuse_req *req);

struct list_head *fuse_pqueue_alloc(void);

/*
 * End a finished request
 */
void fuse_request_end(struct fuse_req *req);

#endif
