/*
 * Copyright (c) 2015 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

#ifndef OVS_CONNTRACK_H
#define OVS_CONNTRACK_H 1

#include <linux/version.h>

struct xt_match;
struct ovs_net;
struct sw_flow_key;
struct sw_flow_actions;
struct ovs_conntrack_info;
struct ovs_key_ct_label;

struct ovs_ct_perdp_data {
	bool xt_v4;
	bool xt_v6;
	struct xt_match *xt_label;
};

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,9,0)
void ovs_ct_init(struct net *, struct ovs_ct_perdp_data *data);
void ovs_ct_exit(struct net *, struct ovs_ct_perdp_data *data);
int ovs_ct_verify(u64 attrs);
int ovs_ct_copy_action(struct net *, const struct nlattr *,
		       const struct sw_flow_key *, struct sw_flow_actions **,
		       bool log);
int ovs_ct_action_to_attr(const struct ovs_conntrack_info *, struct sk_buff *);

int ovs_ct_execute(struct sk_buff *, struct sw_flow_key *,
		   const struct ovs_conntrack_info *);

int ovs_ct_set_mark(struct sk_buff *, struct sw_flow_key *, u32 ct_mark,
		    u32 mask);
u32 ovs_ct_get_mark(const struct sk_buff *skb);
void ovs_ct_get_label(const struct sk_buff *skb,
		      struct ovs_key_ct_label *label);
int ovs_ct_set_label(struct sk_buff *, struct sw_flow_key *,
		     const struct ovs_key_ct_label *label,
		     const struct ovs_key_ct_label *mask);
u8 ovs_ct_get_state(const struct sk_buff *skb);
u16 ovs_ct_get_zone(const struct sk_buff *skb);
bool ovs_ct_state_valid(const struct sw_flow_key *key);
void ovs_ct_free_acts(struct sw_flow_actions *sf_acts);
#else
#include <linux/errno.h>

static inline void ovs_ct_init(struct net *net, struct ovs_ct_perdp_data *data)
{
}

static inline void ovs_ct_exit(struct net *net, struct ovs_ct_perdp_data *data)
{
}

static inline int ovs_ct_verify(u64 attrs)
{
	return -ENOTSUPP;
}

static inline int ovs_ct_copy_action(struct net *net, const struct nlattr *nla,
				     const struct sw_flow_key *key,
				     struct sw_flow_actions **acts, bool log)
{
	return -ENOTSUPP;
}

static inline int ovs_ct_action_to_attr(const struct ovs_conntrack_info *info,
					struct sk_buff *skb)
{
	return -ENOTSUPP;
}

static inline int ovs_ct_execute(struct sk_buff *skb, struct sw_flow_key *key,
				 const struct ovs_conntrack_info *info)
{
	return -ENOTSUPP;
}

static inline u8 ovs_ct_get_state(const struct sk_buff *skb)
{
	return 0;
}

static inline u16 ovs_ct_get_zone(const struct sk_buff *skb)
{
	return 0;
}

static inline u32 ovs_ct_get_mark(const struct sk_buff *skb)
{
	return 0;
}

static inline bool ovs_ct_state_valid(const struct sw_flow_key *key)
{
	return false;
}

static inline int ovs_ct_set_mark(struct sk_buff *skb, struct sw_flow_key *key,
				  u32 ct_mark, u32 mask)
{
	return -ENOTSUPP;
}

static inline void ovs_ct_get_label(const struct sk_buff *skb,
				    struct ovs_key_ct_label *label) { }
static inline int ovs_ct_set_label(struct sk_buff *skb,
				   struct sw_flow_key *key,
				   const struct ovs_key_ct_label *label,
				   const struct ovs_key_ct_label *mask)
{
	return -ENOTSUPP;
}

static inline void ovs_ct_free_acts(struct sw_flow_actions *sf_acts) { }
#endif
#endif /* conntrack.h */
