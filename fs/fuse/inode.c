// SPDX-License-Identifier: GPL-2.0
/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>
*/

#include "dev.h"
#include "fuse_i.h"
#include "fusex.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/statfs.h>
#include <linux/sched.h>
#include <linux/posix_acl.h>
#include <linux/pid_namespace.h>
#include <uapi/linux/magic.h>

MODULE_AUTHOR("Miklos Szeredi <miklos@szeredi.hu>");
MODULE_DESCRIPTION("Filesystem in Userspace");
MODULE_LICENSE("GPL");

struct kmem_cache *fuse_inode_cachep;
struct list_head fuse_conn_list;
DEFINE_MUTEX(fuse_mutex);

unsigned int fuse_max_pages_limit = 256;

static int fuse_inode_eq(struct inode *inode, void *_nodeidp)
{
	u64 nodeid = *(u64 *) _nodeidp;
	if (get_node_id(inode) == nodeid)
		return 1;
	else
		return 0;
}

struct inode *fuse_ilookup(struct fuse_conn *fc, u64 nodeid)
{
	struct fuse_mount *fm_iter;
	struct inode *inode;

	WARN_ON(!rwsem_is_locked(&fc->killsb));
	list_for_each_entry(fm_iter, &fc->mounts, fc_entry) {
		if (!fm_iter->sb)
			continue;

		inode = ilookup5(fm_iter->sb, nodeid, fuse_inode_eq, &nodeid);
		if (inode)
			return inode;
	}

	return NULL;
}

int fuse_reverse_inval_inode(struct fuse_conn *fc, u64 nodeid,
			     loff_t offset, loff_t len)
{
	struct fuse_inode *fi;
	struct inode *inode;
	pgoff_t pg_start;
	pgoff_t pg_end;

	inode = fuse_ilookup(fc, nodeid);
	if (!inode)
		return -ENOENT;

	fi = get_fuse_inode(inode);
	spin_lock(&fi->lock);
	fi->attr_version = atomic64_inc_return(&fc->attr_version);
	spin_unlock(&fi->lock);

	fuse_invalidate_attr(inode);
	forget_all_cached_acls(inode);
	if (offset >= 0) {
		pg_start = offset >> PAGE_SHIFT;
		if (len <= 0)
			pg_end = -1;
		else
			pg_end = (offset + len - 1) >> PAGE_SHIFT;
		invalidate_inode_pages2_range(inode->i_mapping,
					      pg_start, pg_end);
	}
	iput(inode);
	return 0;
}

void fuse_try_prune_one_inode(struct fuse_conn *fc, u64 nodeid)
{
	struct inode *inode;

	inode = fuse_ilookup(fc, nodeid);
	if (!inode)
		return;
	d_prune_aliases(inode);
	iput(inode);
}

void fuse_umount_begin(struct super_block *sb)
{
	fuse_chan_abort(get_fuse_conn_super(sb)->chan);
}

static void fuse_send_destroy(struct fuse_mount *fm)
{
	FUSE_ARGS(args);

	args.opcode = FUSE_DESTROY;
	args.force = true;
	args.nocreds = true;
	fuse_simple_request(fm, &args);
}

void fuse_convert_statfs(struct kstatfs *stbuf, struct fuse_kstatfs *attr)
{
	stbuf->f_type    = FUSE_SUPER_MAGIC;
	stbuf->f_bsize   = attr->bsize;
	stbuf->f_frsize  = attr->frsize;
	stbuf->f_blocks  = attr->blocks;
	stbuf->f_bfree   = attr->bfree;
	stbuf->f_bavail  = attr->bavail;
	stbuf->f_files   = attr->files;
	stbuf->f_ffree   = attr->ffree;
	stbuf->f_namelen = attr->namelen;
	/* fsid is left zero */
}

void fuse_conn_init(struct fuse_conn *fc, struct fuse_mount *fm,
		    struct user_namespace *user_ns, struct fuse_chan *fch)
{
	memset(fc, 0, sizeof(*fc));
	init_rwsem(&fc->killsb);
	refcount_set(&fc->count, 1);
	INIT_LIST_HEAD(&fc->entry);
	atomic64_set(&fc->attr_version, 1);
	fc->pid_ns = get_pid_ns(task_active_pid_ns(current));
	fc->user_ns = get_user_ns(user_ns);
	fc->max_pages_limit = fuse_max_pages_limit;

	INIT_LIST_HEAD(&fc->mounts);
	list_add(&fm->fc_entry, &fc->mounts);
	fm->fc = fc;
	fuse_chan_set_fc(fch, fc);
	fc->chan = fch;
}

static void delayed_release(struct rcu_head *p)
{
	struct fuse_conn *fc = container_of(p, struct fuse_conn, rcu);

	fuse_uring_destruct(fc->chan);
	fuse_chan_free(fc->chan);

	put_user_ns(fc->user_ns);
	kfree(fc);
}

void fuse_conn_put(struct fuse_conn *fc)
{
	if (!refcount_dec_and_test(&fc->count))
		return;

	put_pid_ns(fc->pid_ns);
	call_rcu(&fc->rcu, delayed_release);
}

struct fuse_conn *fuse_conn_get(struct fuse_conn *fc)
{
	refcount_inc(&fc->count);
	return fc;
}

dev_t fuse_conn_get_id(struct fuse_conn *fc)
{
	return fc->dev;
}

void fuse_mount_remove(struct fuse_mount *fm)
{
	struct fuse_conn *fc = fm->fc;

	down_write(&fc->killsb);
	list_del_init(&fm->fc_entry);
	up_write(&fc->killsb);
}

void fuse_conn_destroy(struct fuse_mount *fm)
{
	struct fuse_conn *fc = fm->fc;

	if (fc->destroy)
		fuse_send_destroy(fm);

	fuse_chan_abort(fc->chan);
	fuse_chan_wait_aborted(fc->chan);

	if (!list_empty(&fc->entry)) {
		mutex_lock(&fuse_mutex);
		list_del(&fc->entry);
		fuse_ctl_remove_conn(fc);
		mutex_unlock(&fuse_mutex);
	}
}

void fuse_mount_destroy(struct fuse_mount *fm)
{
	fuse_conn_put(fm->fc);
	kfree_rcu(fm, rcu);
}

static void fuse_inode_init_once(void *foo)
{
	struct inode *inode = foo;

	inode_init_once(inode);
}

static int __init fuse_fs_init(void)
{
	int err;

	fuse_inode_cachep = kmem_cache_create("fuse_inode",
			sizeof(struct fuse_inode), 0,
			SLAB_HWCACHE_ALIGN|SLAB_ACCOUNT|SLAB_RECLAIM_ACCOUNT,
			fuse_inode_init_once);
	err = -ENOMEM;
	if (!fuse_inode_cachep)
		goto out;

	err = fuse_sysctl_register();
	if (err)
		goto out2;

	return 0;

 out2:
	kmem_cache_destroy(fuse_inode_cachep);
 out:
	return err;
}

static void fuse_fs_cleanup(void)
{
	fuse_sysctl_unregister();

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(fuse_inode_cachep);
}

static struct kobject *fuse_kobj;

static int fuse_sysfs_init(void)
{
	int err;

	fuse_kobj = kobject_create_and_add("fuse", fs_kobj);
	if (!fuse_kobj) {
		err = -ENOMEM;
		goto out_err;
	}

	err = sysfs_create_mount_point(fuse_kobj, "connections");
	if (err)
		goto out_fuse_unregister;

	return 0;

 out_fuse_unregister:
	kobject_put(fuse_kobj);
 out_err:
	return err;
}

static void fuse_sysfs_cleanup(void)
{
	sysfs_remove_mount_point(fuse_kobj, "connections");
	kobject_put(fuse_kobj);
}

static int __init fuse_init(void)
{
	int res;

	pr_info("init (API version %i.%i)\n",
		FUSE_KERNEL_VERSION, FUSE_KERNEL_MINOR_VERSION);

	INIT_LIST_HEAD(&fuse_conn_list);
	res = fuse_fs_init();
	if (res)
		goto err;

	res = fuse_dev_init();
	if (res)
		goto err_fs_cleanup;

	res = fuse_sysfs_init();
	if (res)
		goto err_dev_cleanup;

	res = fuse_ctl_init();
	if (res)
		goto err_sysfs_cleanup;

	res = fusex_init();
	if (res)
		goto err_ctl_cleanup;

	return 0;

err_ctl_cleanup:
	fuse_ctl_cleanup();
 err_sysfs_cleanup:
	fuse_sysfs_cleanup();
 err_dev_cleanup:
	fuse_dev_cleanup();
 err_fs_cleanup:
	fuse_fs_cleanup();
 err:
	return res;
}

static void __exit fuse_exit(void)
{
	pr_debug("exit\n");

	fusex_cleanup();
	fuse_ctl_cleanup();
	fuse_sysfs_cleanup();
	fuse_fs_cleanup();
	fuse_dev_cleanup();
}

module_init(fuse_init);
module_exit(fuse_exit);
