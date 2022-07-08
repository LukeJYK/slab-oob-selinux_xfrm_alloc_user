# slab-oob-selinux_xfrm_alloc_user
This is a brief analysis for KASAN: slab-out-of-bounds Read in selinux_xfrm_alloc_user. 

url: [Syzkaller: https://syzkaller.appspot.com/bug?id=b72d20070b541e44e5b91326de68930e51654c81](https://syzkaller.appspot.com/bug?id=b72d20070b541e44e5b91326de68930e51654c81)    

The location of OOB:
```
memcpy(ctx->ctx_str, &uctx[1], str_len);
```
This line of code is from:
```
static int selinux_xfrm_alloc_user(struct xfrm_sec_ctx **ctxp, struct xfrm_user_sec_ctx *uctx, gfp_t gfp)
```
The POC assigns str_len as 768, and str_len is also uctx->ctx_len, so when memcpy tries to read the memory from &uctx[1] to &uctx[1]+768, this will cause OOB-read vulnerability.  

uctx is generated through function copy_from_user_sec_ctx, uctx is the pointer points to the data region of attrs[XFRMA_SEC_CTX].
```
static int copy_from_user_sec_ctx(struct xfrm_policy *pol, struct nlattr **attrs)
{
	struct nlattr *rt = attrs[XFRMA_SEC_CTX];
	struct xfrm_user_sec_ctx *uctx;

	if (!rt)
		return 0;

	uctx = nla_data(rt);
	return security_xfrm_policy_alloc(&pol->security, uctx, GFP_KERNEL);
}
```
The structure of xfrm_user_sec_ctx is:
```
struct xfrm_user_sec_ctx {
	__u16			len;
	__u16			exttype;
	__u8			ctx_alg;  /* LSMs: e.g., selinux == 1 */
	__u8			ctx_doi;
	__u16			ctx_len;
};
```
Usually, xfrm_user_sec_ctx->len = sizeof(xfrm_user_sec_ctx) + xfrm_user_sec_ctx->ctx_len.

In this POC, the uctx->len is 8, is smaller than uctx->ctx_len.

nlattr is first defined in:
```
static int xfrm_user_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh,
			     struct netlink_ext_ack *extack)
```
and nlattr is initilized from nlh.
```
static int __nla_validate_parse(const struct nlattr *head, int len, int maxtype,
				const struct nla_policy *policy,
				unsigned int validate,
				struct netlink_ext_ack *extack,
				struct nlattr **tb, unsigned int depth)
{
	const struct nlattr *nla;
	int rem;

	if (depth >= MAX_POLICY_RECURSION_DEPTH) {
		NL_SET_ERR_MSG(extack,
			       "allowed policy recursion depth exceeded");
		return -EINVAL;
	}

	if (tb)
		memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));

	nla_for_each_attr(nla, head, len, rem) {
		u16 type = nla_type(nla);

		if (type == 0 || type > maxtype) {
			if (validate & NL_VALIDATE_MAXTYPE) {
				NL_SET_ERR_MSG_ATTR(extack, nla,
						    "Unknown attribute type");
				return -EINVAL;
			}
			continue;
		}
		if (policy) {
			int err = validate_nla(nla, maxtype, policy,
					       validate, extack, depth);

			if (err < 0)
				return err;
		}

		if (tb)
			tb[type] = (struct nlattr *)nla;
	}

	if (unlikely(rem > 0)) {
		pr_warn_ratelimited("netlink: %d bytes leftover after parsing attributes in process `%s'.\n",
				    rem, current->comm);
		NL_SET_ERR_MSG(extack, "bytes leftover after parsing attributes");
		if (validate & NL_VALIDATE_TRAILING)
			return -EINVAL;
	}

	return 0;
}
```
nlh is generated from nlmsg_hdr(skb), nlh is the pointer to the data region of skb.
and the skb is also allocated SLAB(small pieces of memory) region from this line of code: data = kmalloc_reserve(size, gfp_mask, node, &pfmemalloc);
The memory region is [ffff88808d161800, ffff88808d161c00), and the &uctx[1] is ffff88808d161934, 308 bytes ahead the begin address of this memory region. And because str_len is 768, the reading region of memory will exceed the end address of the memory region.
