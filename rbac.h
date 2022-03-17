// SPDX-License-Identifier: GPL-2.0

#ifndef _SECURITY_RBAC_H
#define _SECURITY_RBAC_H

#define RBAC_USERS_BKT_BIT 6

struct rbac_user {
	int uid;
	struct rbac_role *role;
	struct hlist_node entry;
	struct rcu_head rcu;
};

#define RBAC_ROLES_BKT_BIT 6

struct rbac_role {
	char role_name[20];
	int hash;
	spinlock_t lock;
	refcount_t usage;
	struct list_head policies;
	struct hlist_node entry;
	struct rcu_head rcu;
};

struct rbac_policy {
	bool allow;
	char value[256];
	struct list_head entry;
	struct rcu_head rcu;
};

#endif