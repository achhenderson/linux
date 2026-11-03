// SPDX-License-Identifier: GPL-2.0
/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>
*/

#include "dev.h"
#include "args.h"
#include "dev_uring_i.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched/signal.h>
#include <linux/uio.h>
#include <linux/miscdevice.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/seq_file.h>

#include "fuse_trace.h"

MODULE_ALIAS_MISCDEV(FUSE_MINOR);
MODULE_ALIAS("devname:fuse");

static DECLARE_WAIT_QUEUE_HEAD(fuse_dev_waitq);

static struct kmem_cache *fuse_req_cachep;

static void fuse_request_init(struct fuse_chan *fch, struct fuse_req *req)
{
	INIT_LIST_HEAD(&req->list);
	init_waitqueue_head(&req->waitq);
	refcount_set(&req->count, 1);
	__set_bit(FR_PENDING, &req->flags);
	req->chan = fch;
}

static struct fuse_req *fuse_request_alloc(struct fuse_chan *fch, gfp_t flags)
{
	struct fuse_req *req = kmem_cache_zalloc(fuse_req_cachep, flags);
	if (req)
		fuse_request_init(fch, req);

	return req;
}

static void fuse_request_free(struct fuse_req *req)
{
	kmem_cache_free(fuse_req_cachep, req);
}

static void __fuse_get_request(struct fuse_req *req)
{
	refcount_inc(&req->count);
}

/* Must be called with > 1 refcount */
static void __fuse_put_request(struct fuse_req *req)
{
	refcount_dec(&req->count);
}

/* FUSE_INIT comes over the ring: it waits here for the server to register */
static bool fuse_block_alloc(struct fuse_chan *fch, bool for_background)
{
	return (for_background && fch->blocked) ||
	       (fch->connected && !fuse_uring_ready(fch));
}

static void fuse_drop_waiting(struct fuse_chan *fch)
{
	/*
	 * lockess check of fch->connected is okay, because atomic_dec_and_test()
	 * provides a memory barrier matched with the one in fuse_chan_wait_aborted()
	 * to ensure no wake-up is missed.
	 */
	if (atomic_dec_and_test(&fch->num_waiting) &&
	    !READ_ONCE(fch->connected)) {
		/* wake up aborters */
		wake_up_all(&fch->blocked_waitq);
	}
}

static struct fuse_req *fuse_get_req(struct fuse_chan *fch, bool for_background)
{
	struct fuse_req *req;
	int err;

	atomic_inc(&fch->num_waiting);

	if (fuse_block_alloc(fch, for_background)) {
		err = -EINTR;
		if (wait_event_state_exclusive(fch->blocked_waitq,
				!fuse_block_alloc(fch, for_background),
				(TASK_KILLABLE | TASK_FREEZABLE)))
			goto out;
	}

	err = -ENOTCONN;
	if (!fch->connected)
		goto out;

	req = fuse_request_alloc(fch, GFP_KERNEL);
	err = -ENOMEM;
	if (!req) {
		if (for_background)
			wake_up(&fch->blocked_waitq);
		goto out;
	}

	__set_bit(FR_WAITING, &req->flags);
	if (for_background)
		__set_bit(FR_BACKGROUND, &req->flags);

	return req;

 out:
	fuse_drop_waiting(fch);
	return ERR_PTR(err);
}

static void fuse_put_request(struct fuse_req *req)
{
	struct fuse_chan *fch = req->chan;

	if (refcount_dec_and_test(&req->count)) {
		if (test_bit(FR_BACKGROUND, &req->flags)) {
			/*
			 * We get here in the unlikely case that a background
			 * request was allocated but not sent
			 */
			spin_lock(&fch->bg_lock);
			if (!fch->blocked)
				wake_up(&fch->blocked_waitq);
			spin_unlock(&fch->bg_lock);
		}

		if (test_bit(FR_WAITING, &req->flags)) {
			__clear_bit(FR_WAITING, &req->flags);
			fuse_drop_waiting(fch);
		}

		fuse_request_free(req);
	}
}

unsigned int fuse_len_args(unsigned int numargs, struct fuse_arg *args)
{
	unsigned nbytes = 0;
	unsigned i;

	for (i = 0; i < numargs; i++)
		nbytes += args[i].size;

	return nbytes;
}

unsigned int fuse_req_hash(u64 unique)
{
	return hash_long(unique, FUSE_PQ_HASH_BITS);
}

void fuse_request_assign_unique(struct fuse_req *req)
{
	req->in.h.unique = atomic64_add_return(FUSE_REQ_ID_STEP, &req->chan->reqctr);

	/* tracepoint captures in.h.unique and in.h.len */
	trace_fuse_request_send(req);
}

void fuse_chan_free(struct fuse_chan *fch)
{
	kfree(fch);
}

struct fuse_chan *fuse_chan_new(void)
{
	struct fuse_chan *fch = kzalloc_obj(struct fuse_chan);
	if (!fch)
		return NULL;

	spin_lock_init(&fch->lock);
	spin_lock_init(&fch->bg_lock);
	init_waitqueue_head(&fch->blocked_waitq);
	atomic_set(&fch->num_waiting, 0);
	fch->max_background = FUSE_DEFAULT_MAX_BACKGROUND;
	fch->blocked = 0;
	fch->connected = 1;

	return fch;
}

struct list_head *fuse_pqueue_alloc(void)
{
	struct list_head *pq = kzalloc_objs(struct list_head, FUSE_PQ_HASH_SIZE);

	if (pq) {
		for (int i = 0; i < FUSE_PQ_HASH_SIZE; i++)
			INIT_LIST_HEAD(&pq[i]);
	}
	return pq;
}

unsigned int fuse_chan_max_background(struct fuse_chan *fch)
{
	return READ_ONCE(fch->max_background);
}

void fuse_chan_max_background_set(struct fuse_chan *fch, unsigned int val)
{
	spin_lock(&fch->bg_lock);
	fch->max_background = val;
	fch->blocked = fch->num_background >= fch->max_background;
	if (!fch->blocked)
		wake_up_nr(&fch->blocked_waitq,
			   fch->max_background - fch->num_background);
	spin_unlock(&fch->bg_lock);
}

unsigned int fuse_chan_num_waiting(struct fuse_chan *fch)
{
	return atomic_read(&fch->num_waiting);
}

void fuse_chan_set_fc(struct fuse_chan *fch, struct fuse_conn *fc)
{
	fch->conn = fc;
}

/* A channel that can't be installed is not usable: abort it */
void fuse_dev_install(struct fuse_dev *fud, struct fuse_chan *fch)
{
	/* Before fud->chan is set: fuse_dev_release() puts this */
	fuse_conn_get(fch->conn);
	/*
	 * Pairs with:
	 *  - xchg() in fuse_dev_release()
	 *  - smp_load_acquire() in fuse_dev_chan_get()
	 */
	if (cmpxchg(&fud->chan, NULL, fch)) {
		fuse_conn_put(fch->conn);
		fuse_chan_abort(fch);
		return;
	}
	wake_up_all(&fuse_dev_waitq);
}

void fuse_dev_put(struct fuse_dev *fud)
{
	if (refcount_dec_and_test(&fud->ref))
		kfree(fud);
}

bool fuse_dev_is_installed(struct fuse_dev *fud)
{
	struct fuse_chan *fch = fuse_dev_chan_get(fud);

	return fch != NULL && fch != FUSE_DEV_CHAN_DISCONNECTED;
}

bool fuse_dev_is_sync_init(struct fuse_dev *fud)
{
	return fud->sync_init;
}

struct fuse_dev *fuse_dev_grab(struct file *file)
{
	struct fuse_dev *fud = fuse_file_to_fud(file);

	refcount_inc(&fud->ref);
	return fud;
}

static void fuse_req_set_len(struct fuse_req *req)
{
	req->in.h.len = sizeof(struct fuse_in_header) +
		fuse_len_args(req->args->in_numargs,
			      (struct fuse_arg *) req->args->in_args);
}

void fuse_request_bg_finish(struct fuse_chan *fch, struct fuse_req *req)
{
	lockdep_assert_held(&fch->bg_lock);

	clear_bit(FR_BACKGROUND, &req->flags);
	if (fch->num_background == fch->max_background) {
		fch->blocked = 0;
		wake_up(&fch->blocked_waitq);
	} else if (!fch->blocked) {
		/*
		 * Wake up next waiter, if any.  It's okay to use
		 * waitqueue_active(), as we've already synced up
		 * fch->blocked with waiters with the wake_up() call
		 * above.
		 */
		if (waitqueue_active(&fch->blocked_waitq))
			wake_up(&fch->blocked_waitq);
	}

	fch->num_background--;
	fch->active_background--;
}

/*
 * This function is called when a request is finished.  Either a reply
 * has arrived or it was aborted (and not yet sent) or some error
 * occurred during communication with userspace, or the device file
 * was closed.  The requester thread is woken up (if still waiting),
 * the 'end' callback is called if given, else the reference to the
 * request is released
 */
void fuse_request_end(struct fuse_req *req)
{
	struct fuse_chan *fch = req->chan;

	if (test_and_set_bit(FR_FINISHED, &req->flags))
		goto put_request;

	trace_fuse_request_end(req);

	WARN_ON(test_bit(FR_PENDING, &req->flags));
	WARN_ON(test_bit(FR_SENT, &req->flags));
	if (test_bit(FR_BACKGROUND, &req->flags)) {
		spin_lock(&fch->bg_lock);
		fuse_request_bg_finish(fch, req);
		spin_unlock(&fch->bg_lock);
	} else {
		/* Wake up waiter sleeping in request_wait_answer() */
		wake_up(&req->waitq);
	}

	if (test_bit(FR_ASYNC, &req->flags))
		req->args->end(req->args, req->out.h.error);
put_request:
	fuse_put_request(req);
}

bool fuse_remove_pending_req(struct fuse_req *req, spinlock_t *lock)
{
	spin_lock(lock);
	if (test_bit(FR_PENDING, &req->flags)) {
		/*
		 * FR_PENDING does not get cleared as the request will end
		 * up in destruction anyway.
		 */
		list_del(&req->list);
		spin_unlock(lock);
		__fuse_put_request(req);
		req->out.h.error = -EINTR;
		return true;
	}
	spin_unlock(lock);
	return false;
}

static void request_wait_answer(struct fuse_req *req)
{
	struct fuse_chan *fch = req->chan;
	int err;

	if (!test_bit(FR_FORCE, &req->flags)) {
		/* Only fatal signals may interrupt this */
		err = wait_event_killable(req->waitq,
					test_bit(FR_FINISHED, &req->flags));
		if (!err)
			return;

		if (req->args->abort_on_kill) {
			fuse_chan_abort(fch);
			goto wait_for_finish;
		}

		if (test_bit(FR_URING, &req->flags) &&
		    fuse_uring_remove_pending_req(req))
			return;
	}

wait_for_finish:
	/*
	 * Either request is already in userspace, or it was forced.
	 * Wait it out.
	 */
	wait_event(req->waitq, test_bit(FR_FINISHED, &req->flags));
}

static void __fuse_request_send(struct fuse_req *req)
{
	BUG_ON(test_bit(FR_BACKGROUND, &req->flags));

	/* acquire extra reference, since request is still needed after
	   fuse_request_end() */
	__fuse_get_request(req);
	fuse_req_set_len(req);
	fuse_uring_queue_fuse_req(req);

	request_wait_answer(req);
	/* Pairs with smp_wmb() in fuse_request_end() */
	smp_rmb();
}

static void fuse_args_to_req(struct fuse_req *req, struct fuse_args *args)
{
	req->in.h.opcode = args->opcode;
	req->in.h.nodeid = args->nodeid;
	req->in.h.uid = args->uid;
	req->in.h.gid = args->gid;
	req->in.h.pid = args->pid;
	req->args = args;
	if (args->end)
		__set_bit(FR_ASYNC, &req->flags);
}

ssize_t fuse_chan_send(struct fuse_chan *fch, struct fuse_args *args)
{
	struct fuse_req *req;
	ssize_t ret;

	if (args->force) {
		atomic_inc(&fch->num_waiting);
		req = fuse_request_alloc(fch, GFP_KERNEL | __GFP_NOFAIL);

		__set_bit(FR_WAITING, &req->flags);
		if (!args->abort_on_kill)
			__set_bit(FR_FORCE, &req->flags);
	} else {
		req = fuse_get_req(fch, false);
		if (IS_ERR(req))
			return PTR_ERR(req);
	}

	fuse_args_to_req(req, args);

	__fuse_request_send(req);
	ret = req->out.h.error;
	if (!ret && args->out_argvar) {
		BUG_ON(args->out_numargs == 0);
		ret = args->out_args[args->out_numargs - 1].size;
	}
	fuse_put_request(req);

	return ret;
}

/*
 * @return true if queued
 */
static bool fuse_request_queue_background(struct fuse_req *req)
{
	struct fuse_chan *fch = req->chan;

	WARN_ON(!test_bit(FR_BACKGROUND, &req->flags));
	if (!test_bit(FR_WAITING, &req->flags)) {
		__set_bit(FR_WAITING, &req->flags);
		atomic_inc(&fch->num_waiting);
	}

	if (!fuse_uring_ready(fch))
		return false;

	fuse_req_set_len(req);
	fuse_request_assign_unique(req);

	return fuse_uring_queue_bq_req(req);
}

int fuse_chan_send_bg(struct fuse_chan *fch, struct fuse_args *args, gfp_t gfp_flags)
{
	struct fuse_req *req;

	if (args->force) {
		req = fuse_request_alloc(fch, gfp_flags);
		if (!req)
			return -ENOMEM;
		__set_bit(FR_BACKGROUND, &req->flags);
	} else {
		req = fuse_get_req(fch, true);
		if (IS_ERR(req))
			return PTR_ERR(req);
	}

	fuse_args_to_req(req, args);

	if (!fuse_request_queue_background(req)) {
		fuse_put_request(req);
		return -ENOTCONN;
	}

	return 0;
}

void fuse_copy_init(struct fuse_copy_state *cs, bool write,
		    struct iov_iter *iter)
{
	memset(cs, 0, sizeof(*cs));
	cs->write = write;
	cs->iter = iter;
}

/* Unmap and put previous page of userspace buffer */
void fuse_copy_finish(struct fuse_copy_state *cs)
{
	if (cs->pg) {
		if (cs->write) {
			flush_dcache_page(cs->pg);
			set_page_dirty_lock(cs->pg);
		}
		put_page(cs->pg);
	}
	cs->pg = NULL;
}

/*
 * Get another pagefull of userspace buffer, and map it to kernel
 * address space
 */
static int fuse_copy_fill(struct fuse_copy_state *cs)
{
	struct page *page;
	size_t off;
	int err;

	fuse_copy_finish(cs);

	err = iov_iter_get_pages2(cs->iter, &page, PAGE_SIZE, 1, &off);
	if (err < 0)
		return err;
	BUG_ON(!err);
	cs->len = err;
	cs->offset = off;
	cs->pg = page;

	return 0;
}

/* Do as much copy to/from userspace buffer as we can */
static int fuse_copy_do(struct fuse_copy_state *cs, void **val, unsigned *size)
{
	unsigned ncpy = min(*size, cs->len);
	void *pgaddr = kmap_local_page(cs->pg);
	void *buf = pgaddr + cs->offset;

	if (cs->write)
		memcpy(buf, *val, ncpy);
	else
		memcpy(*val, buf, ncpy);

	kunmap_local(pgaddr);
	*val += ncpy;
	*size -= ncpy;
	cs->len -= ncpy;
	cs->offset += ncpy;
	cs->ring.copied_sz += ncpy;

	return ncpy;
}

/* Copy a folio in the request to/from the userspace buffer */
static int fuse_copy_folio(struct fuse_copy_state *cs, struct folio *folio,
			   unsigned offset, unsigned count)
{
	int err;

	while (!cs->skip_folio_copy && count) {
		void *mapaddr, *buf;
		unsigned int copy = count;
		unsigned int bytes_copied;

		if (!cs->len) {
			err = fuse_copy_fill(cs);
			if (err)
				return err;
		}

		mapaddr = kmap_local_folio(folio, offset);
		buf = mapaddr;

		if (folio_test_highmem(folio) && count > PAGE_SIZE - offset_in_page(offset))
			copy = PAGE_SIZE - offset_in_page(offset);

		bytes_copied = fuse_copy_do(cs, &buf, &copy);
		kunmap_local(mapaddr);
		offset += bytes_copied;
		count -= bytes_copied;
	}
	if (!cs->write)
		flush_dcache_folio(folio);
	return 0;
}

/* Copy folios in the request to/from userspace buffer */
static int fuse_copy_folios(struct fuse_copy_state *cs, unsigned nbytes)
{
	unsigned i;
	struct fuse_req *req = cs->req;
	struct fuse_args_pages *ap = container_of(req->args, typeof(*ap), args);

	for (i = 0; i < ap->num_folios && nbytes; i++) {
		int err;
		unsigned int offset = ap->descs[i].offset;
		unsigned int count = min(nbytes, ap->descs[i].length);

		err = fuse_copy_folio(cs, ap->folios[i], offset, count);
		if (err)
			return err;

		nbytes -= count;
	}
	return 0;
}

/* Copy a single argument in the request to/from userspace buffer */
int fuse_copy_one(struct fuse_copy_state *cs, void *val, unsigned size)
{
	while (size) {
		if (!cs->len) {
			int err = fuse_copy_fill(cs);
			if (err)
				return err;
		}
		fuse_copy_do(cs, &val, &size);
	}
	return 0;
}

/* Copy request arguments to/from userspace buffer */
int fuse_copy_args(struct fuse_copy_state *cs, unsigned numargs,
		   unsigned argpages, struct fuse_arg *args)
{
	int err = 0;
	unsigned i;

	for (i = 0; !err && i < numargs; i++)  {
		struct fuse_arg *arg = &args[i];
		if (i == numargs - 1 && argpages)
			/* if cs->skip_folio_copy is set, nothing is copied */
			err = fuse_copy_folios(cs, arg->size);
		else
			err = fuse_copy_one(cs, arg->value, arg->size);
	}
	return err;
}

static int fuse_dev_open(struct inode *inode, struct file *file)
{
	struct fuse_dev *fud = kzalloc_obj(struct fuse_dev);

	if (!fud)
		return -ENOMEM;

	refcount_set(&fud->ref, 1);
	file->private_data = fud;
	return 0;
}

struct fuse_dev *fuse_get_dev(struct file *file)
{
	struct fuse_dev *fud = fuse_file_to_fud(file);
	int err;

	if (unlikely(!fuse_dev_chan_get(fud))) {
		/* only block waiting for mount if sync init was requested */
		if (!fud->sync_init)
			return ERR_PTR(-EPERM);

		err = wait_event_interruptible(fuse_dev_waitq, fuse_dev_chan_get(fud) != NULL);
		if (err)
			return ERR_PTR(err);
	}

	return fud;
}

/* Look up request on processing list by unique ID */
struct fuse_req *fuse_request_find(struct fuse_pqueue *fpq, u64 unique)
{
	unsigned int hash = fuse_req_hash(unique);
	struct fuse_req *req;

	list_for_each_entry(req, &fpq->processing[hash], list) {
		if (req->in.h.unique == unique)
			return req;
	}
	return NULL;
}

int fuse_copy_out_args(struct fuse_copy_state *cs, struct fuse_args *args,
		       unsigned nbytes)
{
	/* Headers are separate from args on the ring: args is payload only */
	unsigned int reqsize = fuse_len_args(args->out_numargs, args->out_args);

	if (reqsize < nbytes)
		return -EINVAL;

	if (args->out_argvar) {
		struct fuse_arg *lastarg = &args->out_args[args->out_numargs-1];
		unsigned diffsize = reqsize - nbytes;

		if (diffsize > lastarg->size)
			return -EINVAL;
		lastarg->size -= diffsize;

		if (args->out_var_alloc) {
			lastarg->value = kvmalloc(lastarg->size, GFP_KERNEL);
			if (!lastarg->value)
				return -ENOMEM;
		}
	} else if (reqsize > nbytes) {
		return -EINVAL;
	}
	return fuse_copy_args(cs, args->out_numargs, args->out_pages,
			      args->out_args);
}

/* Abort all requests on the given list (pending or processing) */
void fuse_dev_end_requests(struct list_head *head)
{
	while (!list_empty(head)) {
		struct fuse_req *req;
		req = list_entry(head->next, struct fuse_req, list);
		req->out.h.error = -ECONNABORTED;
		clear_bit(FR_SENT, &req->flags);
		list_del_init(&req->list);
		fuse_request_end(req);
	}
}

/*
 * Abort all requests.
 *
 * Emergency exit in case of a malicious or accidental deadlock, or just a hung
 * filesystem.
 *
 * The same effect is usually achievable through killing the filesystem daemon
 * and all users of the filesystem.
 */
void fuse_chan_abort(struct fuse_chan *fch)
{
	spin_lock(&fch->lock);
	if (fch->connected) {
		/* Background queuing checks fch->connected under bg_lock */
		spin_lock(&fch->bg_lock);
		fch->connected = 0;
		fch->blocked = 0;
		fch->max_background = UINT_MAX;
		spin_unlock(&fch->bg_lock);

		wake_up_all(&fch->blocked_waitq);
		spin_unlock(&fch->lock);

		/*
		 * fch->lock must not be taken to avoid conflicts with io-uring
		 * locks
		 */
		fuse_uring_abort(fch);
	} else {
		spin_unlock(&fch->lock);
	}
}

void fuse_chan_wait_aborted(struct fuse_chan *fch)
{
	/* matches implicit memory barrier in fuse_drop_waiting() */
	smp_mb();
	wait_event(fch->blocked_waitq, fuse_chan_num_waiting(fch) == 0);

	fuse_uring_wait_stopped_queues(fch);
}

static int fuse_dev_release(struct inode *inode, struct file *file)
{
	struct fuse_dev *fud = fuse_file_to_fud(file);
	/* Pairs with cmpxchg() in fuse_dev_install() */
	struct fuse_chan *fch = xchg(&fud->chan, FUSE_DEV_CHAN_DISCONNECTED);

	if (fch) {
		fuse_chan_abort(fch);
		fuse_conn_put(fch->conn);
	}
	fuse_dev_put(fud);
	return 0;
}

static long fuse_dev_ioctl_sync_init(struct file *file)
{
	struct fuse_dev *fud = fuse_file_to_fud(file);

	if (fuse_dev_chan_get(fud))
		return -EINVAL;

	fud->sync_init = true;
	return 0;
}

static long fuse_dev_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	switch (cmd) {
	case FUSE_DEV_IOC_SYNC_INIT:
		return fuse_dev_ioctl_sync_init(file);

	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_PROC_FS
static void fuse_dev_show_fdinfo(struct seq_file *seq, struct file *file)
{
	struct fuse_dev *fud = __fuse_get_dev(file);
	if (!fud)
		return;

	seq_printf(seq, "fuse_connection:\t%u\n", fuse_conn_get_id(fud->chan->conn));
}
#endif

const struct file_operations fuse_dev_operations = {
	.owner		= THIS_MODULE,
	.open		= fuse_dev_open,
	.release	= fuse_dev_release,
	.unlocked_ioctl = fuse_dev_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
	.uring_cmd	= fuse_uring_cmd,
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= fuse_dev_show_fdinfo,
#endif
};

static struct miscdevice fuse_miscdevice = {
	.minor = FUSE_MINOR,
	.name  = "fuse",
	.fops = &fuse_dev_operations,
};

int __init fuse_dev_init(void)
{
	int err = -ENOMEM;
	fuse_req_cachep = kmem_cache_create("fuse_request",
					    sizeof(struct fuse_req),
					    0, 0, NULL);
	if (!fuse_req_cachep)
		goto out;

	err = misc_register(&fuse_miscdevice);
	if (err)
		goto out_cache_clean;

	return 0;

 out_cache_clean:
	kmem_cache_destroy(fuse_req_cachep);
 out:
	return err;
}

void fuse_dev_cleanup(void)
{
	misc_deregister(&fuse_miscdevice);
	kmem_cache_destroy(fuse_req_cachep);
}
