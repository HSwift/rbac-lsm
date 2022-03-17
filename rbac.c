// SPDX-License-Identifier: GPL-2.0

#define RBAC_NAME "rbac"
#define pr_fmt(fmt) RBAC_NAME ": " fmt

#include <linux/security.h>
#include <linux/export.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/magic.h>
#include <linux/namei.h>
#include <linux/hashtable.h>
#include "rbac.h"

static int rbac_enabled = IS_ENABLED(CONFIG_SECURITY_RBAC_LSM);

static void rbac_add_policies(struct rbac_role *role, const bool allow,
			      const char *value)
{
	struct rbac_policy *policy;
	policy = kzalloc(sizeof(struct rbac_policy), GFP_KERNEL);
	policy->allow = allow;
	strcpy(policy->value, value);

	spin_lock(&role->lock);
	list_add_rcu(&policy->entry, &role->policies);
	spin_unlock(&role->lock);
}

static void rbac_clear_policies(struct rbac_role *role)
{
	struct rbac_policy *policy_node;

	spin_lock(&role->lock);
	rcu_read_lock();
	list_for_each_entry_rcu (policy_node, &role->policies, entry) {
		list_del_rcu(&policy_node->entry);
		kfree_rcu(policy_node, rcu);
	}
	rcu_read_unlock();
	spin_unlock(&role->lock);
}

static DEFINE_SPINLOCK(rbac_roles_lock);
static DEFINE_HASHTABLE(rbac_roles_hlist, RBAC_ROLES_BKT_BIT);

static void rbac_add_role(const char *role_name)
{
	struct rbac_role *role_node, *role_node_old;
	role_node = kzalloc(sizeof(struct rbac_role), GFP_KERNEL);
	strcpy(role_node->role_name, role_name);
	role_node->hash = full_name_hash(NULL, role_name, strlen(role_name));
	INIT_LIST_HEAD(&role_node->policies);
	refcount_set(&role_node->usage, 1);
	spin_lock_init(&role_node->lock);

	spin_lock(&rbac_roles_lock);
	rcu_read_lock();
	hash_for_each_possible_rcu (rbac_roles_hlist, role_node_old, entry,
				    role_node->hash) {
		if (role_node_old->hash == role_node->hash &&
		    !strcmp(role_node_old->role_name, role_name)) {
			// keep old one
			goto out;
		}
	}

	hash_add_rcu(rbac_roles_hlist, &role_node->entry, role_node->hash);

out:
	rcu_read_unlock();
	spin_unlock(&rbac_roles_lock);
}

static int rbac_del_role(const char *role_name)
{
	struct rbac_role *role_node;
	int hash = full_name_hash(NULL, role_name, strlen(role_name));
	int ret = -ENOENT;

	spin_lock(&rbac_roles_lock);
	rcu_read_lock();
	hash_for_each_possible_rcu (rbac_roles_hlist, role_node, entry, hash) {
		if (role_node->hash == hash &&
		    !strcmp(role_node->role_name, role_name)) {
			pr_debug("del_role %s refcount=%d", role_name,
				 refcount_read(&role_node->usage));
			if (refcount_read(&role_node->usage) == 1) {
				hlist_del_rcu(&role_node->entry);
				rbac_clear_policies(role_node);
				kfree_rcu(role_node, rcu);
				ret = 0;
				break;
			} else {
				// delete failed, a user holds this role.
				ret = -EBUSY;
				break;
			}
		}
	}
	rcu_read_unlock();
	spin_unlock(&rbac_roles_lock);
	return ret;
}

static struct rbac_role *rbac_get_role_by_name(const char *role_name)
{
	struct rbac_role *role_node = NULL;
	int hash = full_name_hash(NULL, role_name, strlen(role_name));

	rcu_read_lock();
	hash_for_each_possible_rcu (rbac_roles_hlist, role_node, entry, hash) {
		if (role_node->hash == hash &&
		    !strcmp(role_node->role_name, role_name)) {
			rcu_read_unlock();
			return role_node;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static DEFINE_SPINLOCK(rbac_users_lock);
static DEFINE_HASHTABLE(rbac_users_hlist, RBAC_USERS_BKT_BIT);

static void rbac_add_user(const int uid, struct rbac_role *role)
{
	struct rbac_user *user_node, *user_node_old;
	user_node = kzalloc(sizeof(struct rbac_user), GFP_KERNEL);
	user_node->uid = uid;
	user_node->role = role;
	refcount_inc(&role->usage);
	pr_debug("add_user %d -> %s", uid, role->role_name);
	spin_lock(&rbac_users_lock);

	rcu_read_lock();
	hash_for_each_possible_rcu (rbac_users_hlist, user_node_old, entry,
				    uid) {
		if (user_node_old->uid == uid) {
			refcount_dec(&user_node_old->role->usage);
			hlist_replace_rcu(&user_node_old->entry,
					  &user_node->entry);
			kfree_rcu(user_node_old, rcu);
			goto out;
		}
	}

	hash_add_rcu(rbac_users_hlist, &user_node->entry, uid);
out:
	rcu_read_unlock();
	spin_unlock(&rbac_users_lock);
}

static int rbac_del_user(int uid)
{
	struct rbac_user *user_node;
	int ret = -ENOENT;

	spin_lock(&rbac_users_lock);
	rcu_read_lock();
	hash_for_each_possible_rcu (rbac_users_hlist, user_node, entry, uid) {
		if (user_node->uid == uid) {
			hash_del_rcu(&user_node->entry);
			refcount_dec(&user_node->role->usage);
			kfree_rcu(user_node, rcu);
			ret = 0;
			break;
		}
	}
	rcu_read_unlock();
	spin_unlock(&rbac_users_lock);
	return ret;
}

static struct rbac_role *rbac_get_role_by_uid(int uid)
{
	struct rbac_user *user_node;

	rcu_read_lock();
	hash_for_each_possible_rcu (rbac_users_hlist, user_node, entry, uid) {
		if (user_node->uid == uid) {
			rcu_read_unlock();
			return user_node->role;
		}
	}
	rcu_read_unlock();
	return NULL;
}

// append '/' for dir
static char *rbac_real_path(const struct path *path, char *buf, int buf_len)
{
	char *pos;
	struct inode *inode;
	struct dentry *dentry = path->dentry;

	buf[buf_len - 1] = '\0';

	if (dentry->d_op && dentry->d_op->d_dname) {
		pos = dentry->d_op->d_dname(dentry, buf, buf_len - 1);
		goto out;
	}

	pos = d_absolute_path(path, buf, buf_len - 1);
	if (!IS_ERR(pos) && *pos == '/' && pos[1]) {
		inode = d_backing_inode(path->dentry);
		if (S_ISDIR(inode->i_mode)) {
			inode = d_backing_inode(path->dentry);
			if (inode && S_ISDIR(inode->i_mode)) {
				buf[buf_len - 2] = '/';
				buf[buf_len - 1] = '\0';
			}
		}
	}

out:
	return pos;
}

static int rbac_check_access(const struct path *const dir)
{
	const struct cred *cred;
	struct rbac_role *role;
	struct rbac_policy *policy_node;
	char *buf, *pathname;
	unsigned int buf_len = PAGE_SIZE / 2;
	int euid;
	int allow;
	int max_path_len, path_len;

	cred = current_cred();
	euid = from_kuid(cred->user_ns, cred->euid);

	if (rbac_enabled == 0) {
		return 0;
	}
	if (euid == 0) {
		return 0; // no restrict for root
	}
	role = rbac_get_role_by_uid(euid);
	if (role == NULL) {
		return 0; // no rule for this user
	}
	if (dir == NULL) {
		return -ENOENT;
	}
	buf = kmalloc(buf_len, GFP_NOFS);
	if (buf == NULL) {
		return -ENOMEM;
	}
	pathname = rbac_real_path(dir, buf, buf_len);
	if (IS_ERR(pathname)) {
		kfree(buf);
		return PTR_ERR(pathname);
	}

	allow = 1;
	max_path_len = path_len = 0;
	rcu_read_lock();
	list_for_each_entry_rcu (policy_node, &role->policies, entry) {
		path_len = strlen(policy_node->value);
		if (!strncmp(pathname, policy_node->value, path_len)) {
			if (path_len > max_path_len) {
				max_path_len = path_len;
				allow = policy_node->allow;
			}
		}
	}
	rcu_read_unlock();

	if (!allow) {
		//pr_info("deny uid=%d role=%s path=%s\n", euid, role->role_name, pathname);
	}

	kfree(buf);

	return allow ? 0 : -EACCES;
}

static int hook_path_link(struct dentry *const old_dentry,
			  const struct path *const new_dir,
			  struct dentry *const new_dentry)
{
	return rbac_check_access(new_dir);
}

static int hook_path_rename(const struct path *const old_dir,
			    struct dentry *const old_dentry,
			    const struct path *const new_dir,
			    struct dentry *const new_dentry)
{
	return rbac_check_access(new_dir);
}

static int hook_path_mkdir(const struct path *const dir,
			   struct dentry *const dentry, const umode_t mode)
{
	return rbac_check_access(dir);
}

static int hook_path_mknod(const struct path *const dir,
			   struct dentry *const dentry, const umode_t mode,
			   const unsigned int dev)
{
	return rbac_check_access(dir);
}

static int hook_path_symlink(const struct path *const dir,
			     struct dentry *const dentry,
			     const char *const old_name)
{
	return rbac_check_access(dir);
}

static int hook_path_unlink(const struct path *const dir,
			    struct dentry *const dentry)
{
	return rbac_check_access(dir);
}

static int hook_path_rmdir(const struct path *const dir,
			   struct dentry *const dentry)
{
	return rbac_check_access(dir);
}

static int hook_file_open(struct file *const file)
{
	if (file == NULL) {
		return -ENOENT;
	}
	return rbac_check_access(&file->f_path);
}

static struct security_hook_list rbac_hooks[] __lsm_ro_after_init = {

	LSM_HOOK_INIT(path_link, hook_path_link),
	LSM_HOOK_INIT(path_rename, hook_path_rename),
	LSM_HOOK_INIT(path_mkdir, hook_path_mkdir),
	LSM_HOOK_INIT(path_mknod, hook_path_mknod),
	LSM_HOOK_INIT(path_symlink, hook_path_symlink),
	LSM_HOOK_INIT(path_unlink, hook_path_unlink),
	LSM_HOOK_INIT(path_rmdir, hook_path_rmdir),

	LSM_HOOK_INIT(file_open, hook_file_open),
};

static int rbac_parse_role(const char *role_name, char *data)
{
	char *policy_type, *policy_value;
	int policy_allow;
	char *cur = data, *token;
	int state = 0;
	struct rbac_role *role;
	int value_len;
	struct path input_path;
	int ret;

	do {
		token = strsep(&cur, " \n\r\t");
		if (token != 0 && *token != 0) {
			state++;
		} else {
			continue;
		}
		switch (state) {
		case 1:
			policy_type = token;
			break;
		case 2:
			policy_allow = strcmp(token, "allow") == 0 ? 1 : 0;
			break;
		case 3:
			policy_value = token;
			value_len = strlen(policy_value);
			if (value_len >= 256) {
				return -E2BIG;
			}
			break;
		}
	} while (token != 0);

	role = rbac_get_role_by_name(role_name);
	if (role == NULL) {
		return -ENOENT;
	}
	if (state < 3) {
		return -EINVAL;
	}
	ret = kern_path(policy_value, LOOKUP_FOLLOW, &input_path);
	if (ret < 0) {
		return ret;
	}

	rbac_add_policies(role, policy_allow, policy_value);
	return 0;
}

/*
rbac on/off
role add/del [role_name]
role [role_name] fs allow/deny [policy]
role [role_name] net allow/deny [policy]
user [uid] [role_name]
user del [uid]
*/

static ssize_t rbac_secfs_write(struct file *file, const char __user *buf,
				size_t n, loff_t *ppos)
{
	char *data, *cur, *token;
	int err = 0;
	char delim[] = " \n\r\t";

	data = memdup_user_nul(buf, n + 1);
	cur = data;
	if (IS_ERR(cur))
		return PTR_ERR(cur);

	token = strsep(&cur, delim);
	if (!strcmp(token, "rbac")) {
		token = strsep(&cur, delim);
		if (!strcmp(token, "on")) {
			rbac_enabled = 1;
		} else if (!strcmp(token, "off")) {
			rbac_enabled = 0;
		}
	} else if (!strcmp(token, "role")) {
		token = strsep(&cur, delim);
		if (!strcmp(token, "add")) {
			token = strsep(&cur, delim);
			rbac_add_role(token);
		} else if (!strcmp(token, "del")) {
			token = strsep(&cur, delim);
			if (strlen(token) >= 20) {
				err = -E2BIG;
			} else {
				err = rbac_del_role(token);
			}
		} else {
			err = rbac_parse_role(token, cur);
		}
	} else if (!strcmp(token, "user")) {
		token = strsep(&cur, delim);
		if (!strcmp(token, "del")) {
			long uid;
			token = strsep(&cur, delim);
			err = kstrtol(token, 10, &uid);
			if (!err) {
				err = rbac_del_user(uid);
			}
		} else {
			long uid;
			err = kstrtol(token, 10, &uid);
			if (!err) {
				struct rbac_role *role;
				token = strsep(&cur, delim);
				role = rbac_get_role_by_name(token);
				err = -ENOENT;
				if (role != NULL) {
					rbac_add_user(uid, role);
					err = 0;
				}
			}
		}
	}

	kfree(data);
	return err ? err : n;
}

static ssize_t rbac_secfs_read(struct file *filp, char __user *buf,
			       size_t count, loff_t *ppos)
{
	char *temp;
	int offset = 0, bkt = 0;
	struct rbac_role *role_node;
	struct rbac_user *user_node;
	struct rbac_policy *policy_node;

	temp = kmalloc(1024, GFP_KERNEL);
	offset += sprintf(temp + offset, "rbac %s\n",
			  rbac_enabled ? "on" : "off");

	rcu_read_lock();
	hash_for_each_rcu (rbac_roles_hlist, bkt, role_node, entry) {
		char *role_name = role_node->role_name;
		offset += sprintf(temp + offset, "role: %s {\n", role_name);
		list_for_each_entry_rcu (policy_node, &role_node->policies,
					 entry) {
			offset += sprintf(temp + offset, "\t%s: %s\n",
					  policy_node->allow ? "allow" : "deny",
					  policy_node->value);
		}
		offset += sprintf(temp + offset, "}\n");
	}
	offset += sprintf(temp + offset, "\n");

	hash_for_each_rcu (rbac_users_hlist, bkt, user_node, entry) {
		offset += sprintf(temp + offset, "user: %d -> role: %s\n",
				  user_node->uid, user_node->role->role_name);
	}
	rcu_read_unlock();

	temp[offset - 1] = '\n';
	return simple_read_from_buffer(buf, count, ppos, temp, strlen(temp));
}

static const struct file_operations rbac_ops = {
	.read = rbac_secfs_read,
	.write = rbac_secfs_write,
};

static int __init rbac_secfs_init(void)
{
	struct dentry *dentry;

	dentry = securityfs_create_file(RBAC_NAME, 0644, NULL, NULL, &rbac_ops);
	return PTR_ERR_OR_ZERO(dentry);
}

core_initcall(rbac_secfs_init);

static int __init rbac_init(void)
{
	security_add_hooks(rbac_hooks, ARRAY_SIZE(rbac_hooks), RBAC_NAME);
	pr_info("up and running.\n");
	return 0;
}

DEFINE_LSM(rbac) = {
	.name = RBAC_NAME,
	.init = rbac_init,
	.enabled = &rbac_enabled,
};