#include <linux/version.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,9,0)
#ifndef HAVE_NF_CONNTRACK_TMPL_INSERT

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/err.h>
#include <linux/percpu.h>
#include <linux/moduleparam.h>
#include <linux/notifier.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/mm.h>
#include <linux/nsproxy.h>
#include <linux/rculist_nulls.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_timestamp.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_helper.h>

/*
 * deletion from this larval template list happens via nf_ct_put() */
void rpl_nf_conntrack_tmpl_insert(struct net *net, struct nf_conn *tmpl)
{
	__set_bit(IPS_TEMPLATE_BIT, &tmpl->status);
	__set_bit(IPS_CONFIRMED_BIT, &tmpl->status);
#ifdef HAVE_NF_CONNTRACK_TEMPLATES
	nf_conntrack_get(&tmpl->ct_general);

	spin_lock_bh(&nf_conntrack_lock);
	/* Overload tuple linked list to put us in template list. */
	hlist_nulls_add_head_rcu(&tmpl->tuplehash[IP_CT_DIR_ORIGINAL].hnnode,
				 &net->ct.tmpl);
	spin_unlock_bh(&nf_conntrack_lock);
#endif
}
EXPORT_SYMBOL_GPL(rpl_nf_conntrack_tmpl_insert);

#endif /* HAVE_NF_CONNTRACK_TMPL_INSERT */
#endif /* Linux > 3.9 */
