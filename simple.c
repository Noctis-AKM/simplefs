/*
 * A Simple Filesystem for the Linux Kernel.
 *
 * Initial author: Sankar P <sankar.curiosity@gmail.com>
 * License: Creative Commons Zero License - http://creativecommons.org/publicdomain/zero/1.0/
 *
 * TODO: we need to split it into smaller files
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/version.h>

#include "super.h"
#define f_dentry f_path.dentry
/* A super block lock that must be used for any critical section operation on the sb,
 * such as: updating the free_blocks, inodes_count etc. */
static DEFINE_MUTEX(simplefs_sb_lock);
static DEFINE_MUTEX(simplefs_inodes_mgmt_lock);

/* FIXME: This can be moved to an in-memory structure of the simplefs_inode.
 * Because of the global nature of this lock, we cannot create
 * new children (without locking) in two different dirs at a time.
 * They will get sequentially created. If we move the lock
 * to a directory-specific way (by moving it inside inode), the
 * insertion of two children in two different directories can be
 * done in parallel */
static DEFINE_MUTEX(simplefs_directory_children_update_lock);

static struct kmem_cache *sfs_inode_cachep;
static struct kmem_cache *sfs_entry_cachep;

struct simplefs_cache_entry {
	struct simplefs_dir_record record;
	struct list_head list;
	int entry_no;
};

struct simplefs_dir_cache {
	uint64_t dir_children_count;
	struct list_head used;
	struct list_head free;
};


static struct simplefs_dir_cache *simplefs_cache_alloc(void)
{
    struct simplefs_dir_cache *dir_cache;
    dir_cache = kzalloc(sizeof(struct simplefs_dir_cache), GFP_KERNEL);
    if (!dir_cache)
        ERR_PTR(-ENOMEM);

    INIT_LIST_HEAD(&dir_cache->free);
    INIT_LIST_HEAD(&dir_cache->used);

    return dir_cache;
}

static int dir_cache_build(struct simplefs_dir_cache *dir_cache, struct buffer_head *bh)
{
	struct simplefs_dir_record *record;
	struct simplefs_cache_entry *cache_entry;
	int i;

	record = (struct simplefs_dir_record *)bh->b_data;
	for (i = 0; i < SIMPLEFS_MAX_CHILDREN_CNT; i++, record++) {
		cache_entry = kmem_cache_alloc(sfs_entry_cachep, GFP_KERNEL);
		if (!cache_entry)
			return -ENOMEM;

		cache_entry->entry_no = i;

		if (record->inode_no != 0) {
			memcpy(&cache_entry->record, record, sizeof(struct simplefs_dir_record));
			list_add_tail(&cache_entry->list, &dir_cache->used);
		} else {
			list_add_tail(&cache_entry->list, &dir_cache->free);
		}
	}

	return 0;
}

#ifdef SIMPLEFS_DEBUG
static void travers_dir_cache(struct simplefs_dir_cache *dir_cache)
{
	struct simplefs_cache_entry *cache_entry;
	pr_info("print used record:\n");
	list_for_each_entry(cache_entry, &dir_cache->used, list)
		pr_info("record name %s, ino %lld, entry_no %d",
			cache_entry->record.filename, cache_entry->record.inode_no, cache_entry->entry_no);

	pr_info("print free record:\n");
	list_for_each_entry(cache_entry, &dir_cache->free, list)
		pr_info("record entry_no %d", cache_entry->entry_no);
}
#endif

static struct simplefs_cache_entry *used_cache_entry_get(struct simplefs_dir_cache *dir_cache,
										struct dentry *dentry)
{
	struct simplefs_cache_entry *cache_entry;

	list_for_each_entry(cache_entry, &dir_cache->used, list) {
		if (!strcmp(cache_entry->record.filename, dentry->d_name.name)) {
			return cache_entry;
		}
	}

	return NULL;
}

static void cache_entry_insert(struct list_head *head, struct simplefs_cache_entry *cache_entry)
{
	struct simplefs_cache_entry *tmp_entry;
	list_del(&cache_entry->list);

	list_for_each_entry(tmp_entry, head, list) {
		if (cache_entry->entry_no < tmp_entry->entry_no)
			break;
	}

	list_add_tail(&cache_entry->list, &tmp_entry->list);
}

static struct simplefs_cache_entry *free_cache_entry_get(struct simplefs_dir_cache *dir_cache)
{
	return list_first_entry(&dir_cache->free, struct simplefs_cache_entry, list);
}

void simplefs_sb_sync(struct super_block *vsb)
{
	struct buffer_head *bh;
	struct simplefs_super_block *sb = SIMPLEFS_SB(vsb)->sb;

	bh = sb_bread(vsb, SIMPLEFS_SUPERBLOCK_BLOCK_NUMBER);
	BUG_ON(!bh);

	bh->b_data = (char *)sb;
	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);
}

struct simplefs_inode *simplefs_inode_search(struct super_block *sb,
		struct simplefs_inode *start,
		struct simplefs_inode *search)
{
	uint64_t count = 0;
	int icount = SIMPLEFS_DEFAULT_BLOCK_SIZE / sizeof(struct simplefs_inode);
	while (start->inode_no != search->inode_no && count < icount) {
		count++;
		start++;
	}

	if (start->inode_no == search->inode_no) {
		return start;
	}

	return NULL;
}

void simplefs_inode_add(struct super_block *vsb, struct simplefs_inode *inode)
{
	struct simplefs_sb_info *sb_info = SIMPLEFS_SB(vsb);
	struct buffer_head *bh;
	struct simplefs_inode *inode_iterator;

	if (mutex_lock_interruptible(&simplefs_inodes_mgmt_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		return;
	}

	bh = sb_bread(vsb, SIMPLEFS_INODESTORE_BLOCK_NUMBER);
	BUG_ON(!bh);

	inode_iterator = (struct simplefs_inode *)bh->b_data;

	if (mutex_lock_interruptible(&simplefs_sb_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		return;
	}

	/* Append the new inode in the end in the inode store */
	inode_iterator += inode->inode_no;
	memcpy(inode_iterator, inode, sizeof(struct simplefs_inode));
	sb_info->sb->inodes_count++;
	set_bit(inode->inode_no, &sb_info->imap);

	mark_buffer_dirty(bh);
	simplefs_sb_sync(vsb);
	brelse(bh);

	mutex_unlock(&simplefs_sb_lock);
	mutex_unlock(&simplefs_inodes_mgmt_lock);
}

/* This function returns a blocknumber which is free.
 * The block will be removed from the freeblock list.
 *
 * In an ideal, production-ready filesystem, we will not be dealing with blocks,
 * and instead we will be using extents
 *
 * If for some reason, the file creation/deletion failed, the block number
 * will still be marked as non-free. You need fsck to fix this.*/
int simplefs_sb_get_a_freeblock(struct super_block *vsb, uint64_t * out)
{
	struct simplefs_super_block *sb = SIMPLEFS_SB(vsb)->sb;
	int i;
	int ret = 0;

	if (mutex_lock_interruptible(&simplefs_sb_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		ret = -EINTR;
		goto end;
	}

	/* Loop until we find a free block. We start the loop from 3,
	 * as all prior blocks will always be in use */
	for (i = 3; i < SIMPLEFS_MAX_FILESYSTEM_OBJECTS_SUPPORTED; i++) {
		if (sb->free_blocks & (1 << i)) {
			break;
		}
	}

	if (unlikely(i == SIMPLEFS_MAX_FILESYSTEM_OBJECTS_SUPPORTED)) {
		printk(KERN_ERR "No more free blocks available");
		ret = -ENOSPC;
		goto end;
	}

	*out = i;

	/* Remove the identified block from the free list */
	sb->free_blocks &= ~(1 << i);

	simplefs_sb_sync(vsb);

end:
	mutex_unlock(&simplefs_sb_lock);
	return ret;
}

static int simplefs_sb_get_objects_count(struct super_block *vsb,
					 uint64_t * out)
{
	struct simplefs_super_block *sb = SIMPLEFS_SB(vsb)->sb;

	if (mutex_lock_interruptible(&simplefs_inodes_mgmt_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		return -EINTR;
	}
	*out = sb->inodes_count;
	mutex_unlock(&simplefs_inodes_mgmt_lock);

	return 0;
}

static int simplefs_iterate(struct file *filp, struct dir_context *ctx)
{
	loff_t pos;
	struct inode *inode;
	struct super_block *sb;
	struct simplefs_inode *sfs_inode;
	struct dentry *dentry = filp->f_path.dentry;
	struct simplefs_dir_cache *dir_cache = dentry->d_fsdata;
	struct simplefs_cache_entry *cache_entry;

	pos = ctx->pos;
	inode = filp->f_dentry->d_inode;
	sb = inode->i_sb;

	sfs_inode = SIMPLEFS_INODE(inode);

	if (unlikely(!S_ISDIR(sfs_inode->mode))) {
		printk(KERN_ERR
		       "inode [%llu][%lu] for fs object [%s] not a directory\n",
		       sfs_inode->inode_no, inode->i_ino,
		       filp->f_dentry->d_name.name);
		return -ENOTDIR;
	}

	if (pos) {
		/* FIXME: We use a hack of reading pos to figure if we have filled in all data.
		 * We should probably fix this to work in a cursor based model and
		 * use the tokens correctly to not fill too many data in each cursor based call */
		return 0;
	}

	list_for_each_entry(cache_entry, &dir_cache->used, list) {
		dir_emit(ctx, cache_entry->record.filename, SIMPLEFS_FILENAME_MAXLEN,
			cache_entry->record.inode_no, DT_UNKNOWN);
		ctx->pos += sizeof(struct simplefs_dir_record);
		pos += sizeof(struct simplefs_dir_record);
	}

	return 0;
}

/* This functions returns a simplefs_inode with the given inode_no
 * from the inode store, if it exists. */
struct simplefs_inode *simplefs_get_inode(struct super_block *sb,
					  uint64_t inode_no)
{
	struct simplefs_sb_info *sfs_sb_info = SIMPLEFS_SB(sb);
	struct simplefs_inode *sfs_inode = NULL;
	struct simplefs_inode *inode_buffer = NULL;
	struct buffer_head *bh;
	int found = 0;

	/* The inode store can be read once and kept in memory permanently while mounting.
	 * But such a model will not be scalable in a filesystem with
	 * millions or billions of files (inodes) */
	bh = sb_bread(sb, SIMPLEFS_INODESTORE_BLOCK_NUMBER);
	BUG_ON(!bh);

	sfs_inode = (struct simplefs_inode *)bh->b_data;

	/*no 1 is the bit 0 in bitmap*/
	found = (sfs_sb_info->imap >> (inode_no - 1)) & 1;
	if (!found)
		return NULL;

	sfs_inode += inode_no - 1;
	inode_buffer = kmem_cache_alloc(sfs_inode_cachep, GFP_KERNEL);
	BUG_ON(!inode_buffer);
	memcpy(inode_buffer, sfs_inode, sizeof(*inode_buffer));

	brelse(bh);
	return inode_buffer;
}

ssize_t simplefs_read(struct file * filp, char __user * buf, size_t len,
		      loff_t * ppos)
{
	/* After the commit dd37978c5 in the upstream linux kernel,
	 * we can use just filp->f_inode instead of the
	 * f->f_path.dentry->d_inode redirection */
	struct simplefs_inode *inode =
	    SIMPLEFS_INODE(filp->f_path.dentry->d_inode);
	struct buffer_head *bh;

	char *buffer;
	int nbytes;

	if (*ppos >= inode->file_size) {
		/* Read request with offset beyond the filesize */
		return 0;
	}

	bh = sb_bread(filp->f_path.dentry->d_inode->i_sb,
					    inode->data_block_number);

	if (!bh) {
		printk(KERN_ERR "Reading the block number [%llu] failed.",
		       inode->data_block_number);
		return 0;
	}

	buffer = (char *)bh->b_data;
	nbytes = min((size_t) inode->file_size, len);

	if (copy_to_user(buf, buffer, nbytes)) {
		brelse(bh);
		printk(KERN_ERR
		       "Error copying file contents to the userspace buffer\n");
		return -EFAULT;
	}

	brelse(bh);

	*ppos += nbytes;

	return nbytes;
}

/* Save the modified inode */
int simplefs_inode_save(struct super_block *sb, struct simplefs_inode *sfs_inode)
{
	struct simplefs_inode *inode_iterator;
	struct buffer_head *bh;

	bh = sb_bread(sb, SIMPLEFS_INODESTORE_BLOCK_NUMBER);
	BUG_ON(!bh);

	if (mutex_lock_interruptible(&simplefs_sb_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		return -EINTR;
	}

	inode_iterator = simplefs_inode_search(sb,
		(struct simplefs_inode *)bh->b_data,
		sfs_inode);

	if (likely(inode_iterator)) {
		memcpy(inode_iterator, sfs_inode, sizeof(*inode_iterator));
		printk(KERN_INFO "The inode updated\n");

		mark_buffer_dirty(bh);
		sync_dirty_buffer(bh);
	} else {
		mutex_unlock(&simplefs_sb_lock);
		printk(KERN_ERR
		       "The new filesize could not be stored to the inode.");
		return -EIO;
	}

	brelse(bh);
	mutex_unlock(&simplefs_sb_lock);

	return 0;
}

static void simplefs_dentry_release(struct dentry *dentry)
{
	struct simplefs_dir_cache *dir_cache = dentry->d_fsdata;
	struct simplefs_cache_entry *tmp, *cache_entry;

	if (dir_cache) {
		list_for_each_entry_safe(cache_entry, tmp, &dir_cache->free, list) {
			list_del(&cache_entry->list);
			kmem_cache_free(sfs_entry_cachep, cache_entry);
		}

		list_for_each_entry_safe(cache_entry, tmp, &dir_cache->used, list) {
			list_del(&cache_entry->list);
			kmem_cache_free(sfs_entry_cachep, cache_entry);
		}
	}

	kfree(dir_cache);
	dentry->d_fsdata = NULL;
}

static const struct dentry_operations simplefs_dentry_operations = {
	.d_release = simplefs_dentry_release,
};

/* FIXME: The write support is rudimentary. I have not figured out a way to do writes
 * from particular offsets (even though I have written some untested code for this below) efficiently. */
ssize_t simplefs_write(struct file * filp, const char __user * buf, size_t len,
		       loff_t * ppos)
{
	/* After the commit dd37978c5 in the upstream linux kernel,
	 * we can use just filp->f_inode instead of the
	 * f->f_path.dentry->d_inode redirection */
	struct inode *inode;
	struct simplefs_inode *sfs_inode;
	struct buffer_head *bh;
	struct super_block *sb;

	char *buffer;

	int retval;

#if 0
	retval = generic_write_checks(filp, ppos, &len, 0);
	if (retval) {
		return retval;
	}
#endif

	inode = filp->f_path.dentry->d_inode;
	sfs_inode = SIMPLEFS_INODE(inode);
	sb = inode->i_sb;

	bh = sb_bread(filp->f_path.dentry->d_inode->i_sb,
					    sfs_inode->data_block_number);

	if (!bh) {
		printk(KERN_ERR "Reading the block number [%llu] failed.",
		       sfs_inode->data_block_number);
		return 0;
	}
	buffer = (char *)bh->b_data;

	/* Move the pointer until the required byte offset */
	buffer += *ppos;

	if (copy_from_user(buffer, buf, len)) {
		brelse(bh);
		printk(KERN_ERR
		       "Error copying file contents from the userspace buffer to the kernel space\n");
		return -EFAULT;
	}
	*ppos += len;

	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);

	/* Set new size
	 * sfs_inode->file_size = max(sfs_inode->file_size, *ppos);
	 *
	 * FIXME: What to do if someone writes only some parts in between ?
	 * The above code will also fail in case a file is overwritten with
	 * a shorter buffer */
	if (mutex_lock_interruptible(&simplefs_inodes_mgmt_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		return -EINTR;
	}
	sfs_inode->file_size = *ppos;
	retval = simplefs_inode_save(sb, sfs_inode);
	if (retval) {
		len = retval;
	}
	mutex_unlock(&simplefs_inodes_mgmt_lock);

	return len;
}

const struct file_operations simplefs_file_operations = {
	.read = simplefs_read,
	.write = simplefs_write,
};

const struct file_operations simplefs_dir_operations = {
	.owner = THIS_MODULE,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	.iterate = simplefs_iterate,
#else
	.readdir = simplefs_readdir,
#endif
};

struct dentry *simplefs_lookup(struct inode *parent_inode,
			       struct dentry *child_dentry, unsigned int flags);

static int simplefs_create(struct inode *dir, struct dentry *dentry,
			   umode_t mode, bool excl);

static int simplefs_mkdir(struct inode *dir, struct dentry *dentry,
			  umode_t mode);

static int simplefs_unlink(struct inode *dir, struct dentry *dentry);

static struct inode_operations simplefs_inode_ops = {
	.create = simplefs_create,
	.lookup = simplefs_lookup,
	.mkdir = simplefs_mkdir,
	.unlink = simplefs_unlink,
};

static int simplefs_create_fs_object(struct inode *dir, struct dentry *dentry,
				     umode_t mode)
{
	struct inode *inode;
	struct simplefs_inode *sfs_inode;
	struct super_block *sb = dir->i_sb;
	struct simplefs_inode *parent_dir_inode;
	struct buffer_head *bh;
	struct simplefs_dir_record *dir_contents_datablock;
	struct dentry *parent_dentry = dentry->d_parent;
	struct simplefs_cache_entry *cache_entry;
	struct simplefs_dir_cache * dir_cache;
	struct simplefs_sb_info *sb_info = SIMPLEFS_SB(sb);
	uint64_t count;
	int ret;

	BUG_ON(parent_dentry->d_inode != dir);

	dir_cache = (struct simplefs_dir_cache *)parent_dentry->d_fsdata;
	BUG_ON(!dir_cache);

	if (mutex_lock_interruptible(&simplefs_directory_children_update_lock)) {
		sfs_trace("Failed to acquire mutex lock\n");
		return -EINTR;
	}

	ret = simplefs_sb_get_objects_count(sb, &count);
	if (ret < 0) {
		mutex_unlock(&simplefs_directory_children_update_lock);
		return ret;
	}

	if (unlikely(count >= SIMPLEFS_MAX_FILESYSTEM_OBJECTS_SUPPORTED)) {
		/* The above condition can be just == insted of the >= */
		printk(KERN_ERR
		       "Maximum number of objects supported by simplefs is already reached");
		mutex_unlock(&simplefs_directory_children_update_lock);
		return -ENOSPC;
	}

	if (!S_ISDIR(mode) && !S_ISREG(mode)) {
		printk(KERN_ERR
		       "Creation request but for neither a file nor a directory");
		mutex_unlock(&simplefs_directory_children_update_lock);
		return -EINVAL;
	}

	/* create inode */
	inode = new_inode(sb);
	if (!inode) {
		mutex_unlock(&simplefs_directory_children_update_lock);
		return -ENOMEM;
	}

	inode->i_sb = sb;
	inode->i_op = &simplefs_inode_ops;
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	//inode->i_ino = (count + SIMPLEFS_START_INO - SIMPLEFS_RESERVED_INODES + 1);
	inode->i_ino = ffz(sb_info->imap);

	sfs_inode = kmem_cache_alloc(sfs_inode_cachep, GFP_KERNEL);
	sfs_inode->inode_no = inode->i_ino;
	inode->i_private = sfs_inode;
	sfs_inode->mode = mode;

	if (S_ISDIR(mode)) {
		printk(KERN_INFO "New directory creation request\n");
		sfs_inode->dir_children_count = 0;
		inode->i_fop = &simplefs_dir_operations;
	} else if (S_ISREG(mode)) {
		printk(KERN_INFO "New file creation request\n");
		sfs_inode->file_size = 0;
		inode->i_fop = &simplefs_file_operations;
	}

	/* First get a free block and update the free map,
	 * Then add inode to the inode store and update the sb inodes_count,
	 * Then update the parent directory's inode with the new child.
	 *
	 * The above ordering helps us to maintain fs consistency
	 * even in most crashes
	 */
	ret = simplefs_sb_get_a_freeblock(sb, &sfs_inode->data_block_number);
	if (ret < 0) {
		printk(KERN_ERR "simplefs could not get a freeblock");
		mutex_unlock(&simplefs_directory_children_update_lock);
		return ret;
	}

	simplefs_inode_add(sb, sfs_inode);
	/* Read directory */
	parent_dir_inode = SIMPLEFS_INODE(dir);
	/* get a free place for record */
	cache_entry = free_cache_entry_get(dir_cache);
	BUG_ON(!cache_entry);

	bh = sb_bread(sb, parent_dir_inode->data_block_number);
	BUG_ON(!bh);

	dir_contents_datablock = (struct simplefs_dir_record *)bh->b_data;

	/* Navigate to the last record in the directory contents */
	dir_contents_datablock += cache_entry->entry_no;

	dir_contents_datablock->inode_no = sfs_inode->inode_no;
	strcpy(dir_contents_datablock->filename, dentry->d_name.name);
	memcpy(&cache_entry->record, dir_contents_datablock, sizeof(struct simplefs_dir_record));
	cache_entry_insert(&dir_cache->used, cache_entry);

#ifdef SIMPLEFS_DEBUG
	travers_dir_cache(dir_cache);
#endif

	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);

	if (mutex_lock_interruptible(&simplefs_inodes_mgmt_lock)) {
		mutex_unlock(&simplefs_directory_children_update_lock);
		sfs_trace("Failed to acquire mutex lock\n");
		return -EINTR;
	}

	parent_dir_inode->dir_children_count++;
	ret = simplefs_inode_save(sb, parent_dir_inode);
	if (ret) {
		mutex_unlock(&simplefs_inodes_mgmt_lock);
		mutex_unlock(&simplefs_directory_children_update_lock);

		/* TODO: Remove the newly created inode from the disk and in-memory inode store
		 * and also update the superblock, freemaps etc. to reflect the same.
		 * Basically, Undo all actions done during this create call */
		return ret;
	}

	mutex_unlock(&simplefs_inodes_mgmt_lock);
	mutex_unlock(&simplefs_directory_children_update_lock);

	inode_init_owner(inode, dir, mode);
	d_add(dentry, inode);

	return 0;
}

static int simplefs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct buffer_head *bh;
	struct super_block *sb = dir->i_sb;
	int err = -ENOENT;
	struct inode *inode = d_inode(dentry);
	struct simplefs_inode *sfs_inode = SIMPLEFS_INODE(inode);
	struct simplefs_inode *dir_sfs_inode = SIMPLEFS_INODE(dir);
	struct simplefs_dir_record *record;
	struct dentry *parent_dentry = dentry->d_parent;
	struct simplefs_cache_entry *cache_entry;
	struct simplefs_dir_cache * dir_cache;
	struct simplefs_sb_info *sb_info = SIMPLEFS_SB(sb);

	BUG_ON(parent_dentry->d_inode != dir);

	dir_cache = (struct simplefs_dir_cache *)parent_dentry->d_fsdata;
	BUG_ON(!dir_cache);

	if (mutex_lock_interruptible(&simplefs_directory_children_update_lock))
	{
		sfs_trace("Failed to acquire mutex lock\n");
		return -EINTR;
	}

	bh = sb_bread(sb, dir_sfs_inode->data_block_number);
	BUG_ON(!bh);

	cache_entry = used_cache_entry_get(dir_cache, dentry);
	if (!cache_entry)
		goto end_unlink;

	record = (struct simplefs_dir_record *)bh->b_data;
	record += cache_entry->entry_no;
	record->inode_no = 0;

	memset(&cache_entry->record, 0, sizeof(struct simplefs_dir_record));
	cache_entry_insert(&dir_cache->free, cache_entry);

	dir->i_ctime = dir->i_mtime = current_time(dir);

	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);

	if (mutex_lock_interruptible(&simplefs_inodes_mgmt_lock))
	{
		sfs_trace("Failed to acquire mutex lock\n");
		mutex_unlock(&simplefs_directory_children_update_lock);
		return -EINTR;
	}

	dir_sfs_inode->dir_children_count--;
	err = simplefs_inode_save(sb, dir_sfs_inode);
	if (err)
	{
		mutex_unlock(&simplefs_inodes_mgmt_lock);
		mutex_unlock(&simplefs_directory_children_update_lock);
		return err;
	}

	clear_bit(sfs_inode->inode_no, &sb_info->imap);
	sfs_inode->inode_no = 0;

	err = simplefs_inode_save(sb, sfs_inode);
	if (err)
	{
		mutex_unlock(&simplefs_inodes_mgmt_lock);
		mutex_unlock(&simplefs_directory_children_update_lock);
		return err;
	}

	mutex_unlock(&simplefs_inodes_mgmt_lock);
	mutex_unlock(&simplefs_directory_children_update_lock);
	inode->i_ctime = dir->i_ctime;
	return 0;

end_unlink:
	return err;
}

static int simplefs_mkdir(struct inode *dir, struct dentry *dentry,
			  umode_t mode)
{
	/* I believe this is a bug in the kernel, for some reason, the mkdir callback
	 * does not get the S_IFDIR flag set. Even ext2 sets is explicitly */
	return simplefs_create_fs_object(dir, dentry, S_IFDIR | mode);
}

static int simplefs_create(struct inode *dir, struct dentry *dentry,
			   umode_t mode, bool excl)
{
	return simplefs_create_fs_object(dir, dentry, mode);
}

struct dentry *simplefs_lookup(struct inode *parent_inode,
			       struct dentry *child_dentry, unsigned int flags)
{
	struct simplefs_inode *parent = SIMPLEFS_INODE(parent_inode);
	struct super_block *sb = parent_inode->i_sb;
	struct buffer_head *bh;
	struct dentry *parent_dentry;
	struct simplefs_dir_cache *dir_cache;
	struct simplefs_cache_entry *cache_entry;
	struct inode *inode;
	struct simplefs_inode *sfs_inode;

	parent_dentry = child_dentry->d_parent;
    //BUG_ON(parent_dentry->d_inode != parent_inode);
    if (parent_dentry->d_inode != parent_inode)
		return ERR_PTR(-ENOENT);

    dir_cache = (struct simplefs_dir_cache *)parent_dentry->d_fsdata;

	if (!dir_cache) {
		parent_dentry->d_fsdata = simplefs_cache_alloc();
		if (IS_ERR(parent_dentry->d_fsdata))
		    return parent_dentry->d_fsdata;

		bh = sb_bread(sb, parent->data_block_number);
		BUG_ON(!bh);

		dir_cache = (struct simplefs_dir_cache *)parent_dentry->d_fsdata;
		dir_cache_build(dir_cache, bh);
	}

#ifdef SIMPLEFS_DEBUG
	travers_dir_cache(dir_cache);
#endif

	cache_entry = used_cache_entry_get(dir_cache, child_dentry);
	if (!cache_entry)
		goto out;

	/* FIXME: There is a corner case where if an allocated inode,
	 * is not written to the inode store, but the inodes_count is
	 * incremented. Then if the random string on the disk matches
	 * with the filename that we are comparing above, then we
	 * will use an invalid uninitialized inode */
	sfs_inode = simplefs_get_inode(sb, cache_entry->record.inode_no);
	if (!sfs_inode)
		return ERR_PTR(-ENOENT);

	inode = new_inode(sb);
	inode->i_ino = cache_entry->record.inode_no;
	inode_init_owner(inode, parent_inode, sfs_inode->mode);
	inode->i_sb = sb;
	inode->i_op = &simplefs_inode_ops;

	if (S_ISDIR(inode->i_mode))
		inode->i_fop = &simplefs_dir_operations;
	else if (S_ISREG(inode->i_mode))
		inode->i_fop = &simplefs_file_operations;
	else
		printk(KERN_ERR
		       "Unknown inode type. Neither a directory nor a file");

	/* FIXME: We should store these times to disk and retrieve them */
	inode->i_atime = inode->i_mtime = inode->i_ctime =
	    current_time(inode);

	inode->i_private = sfs_inode;

	d_add(child_dentry, inode);
#if 0
	printk(KERN_ERR
	       "No inode found for the filename [%s]\n",
	       child_dentry->d_name.name);
#endif

out:
	return NULL;
}


/**
 * Simplest
 */
void simplefs_destory_inode(struct inode *inode)
{
	struct simplefs_inode *sfs_inode = SIMPLEFS_INODE(inode);

	printk(KERN_INFO "Freeing private data of inode %p (%lu)\n",
	       sfs_inode, inode->i_ino);
	kmem_cache_free(sfs_inode_cachep, sfs_inode);
}

static const struct super_operations simplefs_sops = {
	.destroy_inode = simplefs_destory_inode,
};

#ifdef SIMPLEFS_DEBUG
static void imap_dump(struct super_block *sb)
{
	struct simplefs_sb_info *sb_info = sb->s_fs_info;
	pr_info("starting imap dump: imap %lu\n",  sb_info->imap);
}
#endif

static void fill_imap(struct super_block *sb)
{
	int i;
	struct simplefs_sb_info *sb_info = sb->s_fs_info;
	struct simplefs_inode *simple_inode;
	struct buffer_head *bh;
	int icount = SIMPLEFS_DEFAULT_BLOCK_SIZE / sizeof(struct simplefs_inode);

	bh = sb_bread(sb, SIMPLEFS_INODESTORE_BLOCK_NUMBER);
	simple_inode = (struct simplefs_inode *)bh->b_data;

	for (i = 0; i < SIMPLEFS_START_INO; i++)
		set_bit(i, &sb_info->imap);

	simple_inode += SIMPLEFS_START_INO;
	for (i = SIMPLEFS_START_INO; i < icount; i++) {
		if (simple_inode->inode_no != 0) {
			pr_err("func %s, line %d, ino %lld\n", __func__, __LINE__, simple_inode->inode_no);
			set_bit(i, &sb_info->imap);
		}
		simple_inode++;
	}

	brelse(bh);
#ifdef SIMPLEFS_DEBUG
	imap_dump(sb);
#endif
}

/* This function, as the name implies, Makes the super_block valid and
 * fills filesystem specific information in the super block */
int simplefs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *root_inode;
	struct buffer_head *bh;
	struct simplefs_super_block *sb_disk;
	struct simplefs_sb_info *sb_info;
	int ret = -EPERM;

	bh = sb_bread(sb, SIMPLEFS_SUPERBLOCK_BLOCK_NUMBER);
	BUG_ON(!bh);

	sb_disk = (struct simplefs_super_block *)bh->b_data;

	printk(KERN_INFO "The magic number obtained in disk is: [%llu]\n",
	       sb_disk->magic);

	if (unlikely(sb_disk->magic != SIMPLEFS_MAGIC)) {
		printk(KERN_ERR
		       "The filesystem that you try to mount is not of type simplefs. Magicnumber mismatch.");
		goto release;
	}

	if (unlikely(sb_disk->block_size != SIMPLEFS_DEFAULT_BLOCK_SIZE)) {
		printk(KERN_ERR
		       "simplefs seem to be formatted using a non-standard block size.");
		goto release;
	}

	printk(KERN_INFO
	       "simplefs filesystem of version [%llu] formatted with a block size of [%llu] detected in the device.\n",
	       sb_disk->version, sb_disk->block_size);

	/* A magic number that uniquely identifies our filesystem type */
	sb->s_magic = SIMPLEFS_MAGIC;

	/* For all practical purposes, we will be using this s_fs_info as the super block */
	sb_info = kzalloc(sizeof(struct simplefs_sb_info), GFP_KERNEL);
	if (!sb_info) {
		brelse(bh);
		return -ENOMEM;
	}

	sb_info->sb = sb_disk;
	sb_info->bh = bh;
	sb->s_fs_info = sb_info;
	fill_imap(sb);

	sb->s_maxbytes = SIMPLEFS_DEFAULT_BLOCK_SIZE;
	sb->s_op = &simplefs_sops;
	sb->s_d_op = &simplefs_dentry_operations;

	root_inode = new_inode(sb);
	root_inode->i_ino = SIMPLEFS_ROOTDIR_INODE_NUMBER;
	inode_init_owner(root_inode, NULL, S_IFDIR);
	root_inode->i_sb = sb;
	root_inode->i_op = &simplefs_inode_ops;
	root_inode->i_fop = &simplefs_dir_operations;
	root_inode->i_atime = root_inode->i_mtime = root_inode->i_ctime =
	    current_time(root_inode);

	root_inode->i_private =
	    simplefs_get_inode(sb, SIMPLEFS_ROOTDIR_INODE_NUMBER);

	/* TODO: move such stuff into separate header. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
	sb->s_root = d_make_root(root_inode);
#else
	sb->s_root = d_alloc_root(root_inode);
	if (!sb->s_root)
		iput(root_inode);
#endif

	if (!sb->s_root) {
		ret = -ENOMEM;
		kfree(sb_info);
		goto release;
	}

	return 0;
release:
	brelse(bh);
	return ret;
}

static struct dentry *simplefs_mount(struct file_system_type *fs_type,
				     int flags, const char *dev_name,
				     void *data)
{
	struct dentry *ret;

	ret = mount_bdev(fs_type, flags, dev_name, data, simplefs_fill_super);

	if (unlikely(IS_ERR(ret)))
		printk(KERN_ERR "Error mounting simplefs");
	else
		printk(KERN_INFO "simplefs is succesfully mounted on [%s]\n",
		       dev_name);

	return ret;
}

static void simplefs_kill_superblock(struct super_block *sb)
{
	struct simplefs_sb_info *sb_info = sb->s_fs_info;
	printk(KERN_INFO
	       "simplefs superblock is destroyed. Unmount succesful.\n");
	/* This is just a dummy function as of now. As our filesystem gets matured,
	 * we will do more meaningful operations here */

	brelse(sb_info->bh);
	kfree(sb_info);
	kill_block_super(sb);
	return;
}

struct file_system_type simplefs_fs_type = {
	.owner = THIS_MODULE,
	.name = "simplefs",
	.mount = simplefs_mount,
	.kill_sb = simplefs_kill_superblock,
	.fs_flags = FS_REQUIRES_DEV,
};

static int simplefs_init(void)
{
	int ret;

	sfs_inode_cachep = kmem_cache_create("sfs_inode_cache",
	                                     sizeof(struct simplefs_inode),
	                                     0,
	                                     (SLAB_RECLAIM_ACCOUNT| SLAB_MEM_SPREAD),
	                                     NULL);
	if (!sfs_inode_cachep) {
		return -ENOMEM;
	}

	sfs_entry_cachep = kmem_cache_create("sfs_entry_cachep",
										sizeof(struct simplefs_cache_entry),
										0,
										(SLAB_RECLAIM_ACCOUNT| SLAB_MEM_SPREAD),
										NULL);

	if (!sfs_entry_cachep) {
		kmem_cache_destroy(sfs_inode_cachep);
		return -ENOMEM;
	}

	ret = register_filesystem(&simplefs_fs_type);
	if (likely(ret == 0))
		printk(KERN_INFO "Sucessfully registered simplefs\n");
	else
		printk(KERN_ERR "Failed to register simplefs. Error:[%d]", ret);

	return ret;
}

static void simplefs_exit(void)
{
	int ret;

	ret = unregister_filesystem(&simplefs_fs_type);
	kmem_cache_destroy(sfs_entry_cachep);
	kmem_cache_destroy(sfs_inode_cachep);

	if (likely(ret == 0))
		printk(KERN_INFO "Sucessfully unregistered simplefs\n");
	else
		printk(KERN_ERR "Failed to unregister simplefs. Error:[%d]",
		       ret);
}

module_init(simplefs_init);
module_exit(simplefs_exit);

MODULE_LICENSE("CC0");
MODULE_AUTHOR("Sankar P");
