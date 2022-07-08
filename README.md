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
The POC assigns str_len as 768, so when memcpy tries to read the memory from &uctx[1] to &uctx[1]+768, this will cause OOB-read vulnerability.  
