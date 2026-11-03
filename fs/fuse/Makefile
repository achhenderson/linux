# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the FUSE filesystem.
#

# Needed for trace events
ccflags-y = -I$(src)

obj-$(CONFIG_FUSE_FS) += fuse.o

fuse-y := trace.o	# put trace.o first so we see ftrace errors sooner
fuse-y += dev.o dev_uring.o dir.o inode.o control.o readdir.o req.o notify.o fusex.o
fuse-$(CONFIG_SYSCTL) += sysctl.o
