// SPDX-License-Identifier: GPL-2.0-only

#include "dev.h"
#include "fuse_i.h"

#include <linux/pagemap.h>

static int fuse_notify_inval_inode(struct fuse_conn *fc, unsigned int size,
				   struct fuse_copy_state *cs)
{
	struct fuse_notify_inval_inode_out outarg;
	int err;

	if (size != sizeof(outarg))
		return -EINVAL;

	err = fuse_copy_one(cs, &outarg, sizeof(outarg));
	if (err)
		return err;
	fuse_copy_finish(cs);

	down_read(&fc->killsb);
	err = fuse_reverse_inval_inode(fc, outarg.ino,
				       outarg.off, outarg.len);
	up_read(&fc->killsb);
	return err;
}

static int fuse_notify_inval_entry(struct fuse_conn *fc, unsigned int size,
				   struct fuse_copy_state *cs)
{
	struct fuse_notify_inval_entry_out outarg;
	int err;
	char *buf;
	struct qstr name;

	if (size < sizeof(outarg))
		return -EINVAL;

	err = fuse_copy_one(cs, &outarg, sizeof(outarg));
	if (err)
		return err;

	if (outarg.namelen > FUSE_NAME_LOW_MAX)
		return -ENAMETOOLONG;

	err = -EINVAL;
	if (size != sizeof(outarg) + outarg.namelen + 1)
		return -EINVAL;

	buf = kzalloc(outarg.namelen + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	name.name = buf;
	name.len = outarg.namelen;
	err = fuse_copy_one(cs, buf, outarg.namelen + 1);
	if (err)
		goto err;
	fuse_copy_finish(cs);
	buf[outarg.namelen] = 0;

	down_read(&fc->killsb);
	err = fuse_reverse_inval_entry(fc, outarg.parent, 0, &name);
	up_read(&fc->killsb);
err:
	kfree(buf);
	return err;
}

static int fuse_notify_delete(struct fuse_conn *fc, unsigned int size,
			      struct fuse_copy_state *cs)
{
	struct fuse_notify_delete_out outarg;
	int err;
	char *buf;
	struct qstr name;

	if (size < sizeof(outarg))
		return -EINVAL;

	err = fuse_copy_one(cs, &outarg, sizeof(outarg));
	if (err)
		return err;

	if (outarg.namelen > FUSE_NAME_LOW_MAX)
		return -ENAMETOOLONG;

	if (size != sizeof(outarg) + outarg.namelen + 1)
		return -EINVAL;

	buf = kzalloc(outarg.namelen + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	name.name = buf;
	name.len = outarg.namelen;
	err = fuse_copy_one(cs, buf, outarg.namelen + 1);
	if (err)
		goto err;
	fuse_copy_finish(cs);
	buf[outarg.namelen] = 0;

	down_read(&fc->killsb);
	err = fuse_reverse_inval_entry(fc, outarg.parent, outarg.child, &name);
	up_read(&fc->killsb);
err:
	kfree(buf);
	return err;
}

static int fuse_notify_prune(struct fuse_conn *fc, unsigned int size,
			     struct fuse_copy_state *cs)
{
	struct fuse_notify_prune_out outarg;
	const unsigned int batch = 512;
	u64 *nodeids __free(kfree) = kmalloc(sizeof(u64) * batch, GFP_KERNEL);
	unsigned int num, i;
	int err;

	if (!nodeids)
		return -ENOMEM;

	if (size < sizeof(outarg))
		return -EINVAL;

	err = fuse_copy_one(cs, &outarg, sizeof(outarg));
	if (err)
		return err;

	if (size - sizeof(outarg) != array_size(outarg.count, sizeof(u64)))
		return -EINVAL;

	for (; outarg.count; outarg.count -= num) {
		num = min(batch, outarg.count);
		err = fuse_copy_one(cs, nodeids, num * sizeof(u64));
		if (err)
			return err;

		scoped_guard(rwsem_read, &fc->killsb) {
			for (i = 0; i < num; i++)
				fuse_try_prune_one_inode(fc, nodeids[i]);
		}
	}
	return 0;
}

int fuse_notify(struct fuse_conn *fc, enum fuse_notify_code code,
		unsigned int size, struct fuse_copy_state *cs)
{
	switch (code) {
	case FUSE_NOTIFY_INVAL_INODE:
		return fuse_notify_inval_inode(fc, size, cs);

	case FUSE_NOTIFY_INVAL_ENTRY:
		return fuse_notify_inval_entry(fc, size, cs);

	case FUSE_NOTIFY_DELETE:
		return fuse_notify_delete(fc, size, cs);

	case FUSE_NOTIFY_PRUNE:
		return fuse_notify_prune(fc, size, cs);

	default:
		return -EINVAL;
	}
}
