#ifndef __NF_CONNTRACK_WRAPPER_H
#define __NF_CONNTRACK_WRAPPER_H 1

#include <linux/version.h>
#include_next <net/netfilter/nf_conntrack.h>

#ifndef HAVE_NF_CONNTRACK_TMPL_INSERT
void rpl_nf_conntrack_tmpl_insert(struct net *net, struct nf_conn *tmpl);
#define nf_conntrack_tmpl_insert rpl_nf_conntrack_tmpl_insert
#endif

#endif /* net/netfilter/nf_conntrack.h */
