#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/cred.h>
#include <sys/debug.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/inline.h>
#include <sys/kmem.h>
#include <sys/pathname.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/kobj.h>
#include <sys/uio.h>
#include <sys/var.h>
#include <sys/mode.h>
#include <sys/poll.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <sys/procfs.h>
#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <vm/rm.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_vn.h>
#include <vm/hat.h>

#include <kmod.h>
#include <zzlib.h>

static int ptrace_init(unsigned int id);
static int ptrace_fini(void);
static void ptrace_recv(kmsg_t *kp);

struct zz_kmod ptrace_kmod = {
	ptrace_init,
	ptrace_fini,
	ptrace_recv,
	"PTRACE",
	ZZ_VERSION
};

static vnodeops_t * prvnodeopsp;

static unsigned int	ptrace_id;
#define	set_my_id(id)	(ptrace_id = id)
#define	get_my_id()	(ptrace_id)

static int (*orig_propen)(vnode_t **, int, struct cred *);
static int (*orig_prwrite)(vnode_t *, uio_t *, int, struct cred *);

#ifdef	DEBUG
# define	dprintf(x)	zz_printf x 
#else
# define	dprintf(x)	/* nothing */
#endif /* DEBUG */

static void
ptrace_event(void)
{
	kmsg_t	* kp;

	dprintf(("ptrace: generating an event"));
	if ((kp = kmsg_new_event(PROCESS_HIJACK)) == NULL)
		return;

	kp->to = BCOM;
	kp->from = get_my_id();

	kmsg_send(kp);
	kmsg_free(kp);

	dprintf(("ptrace: sent event"));
}

static int
zz_propen(vnode_t **vpp, int flag, struct cred * cr)
{
	vnode_t	* vp = *vpp;
	prnode_t *pnp = VTOP(vp);
	kmsg_t	* kp;


	dprintf(("ptrace: open(%p, %d, %p)", vpp, flag, cr));

	dprintf(("pnp->pr_type = %d", pnp->pr_type));

	switch (pnp->pr_type) {
	case PR_AS:	/* address space */
	case PR_CTL:	/* control file */
	case PR_MAP:	/* object maps */
	case PR_OBJECT:	/* the a.out object */
	case PR_LWPCTL:	/* light weight process control file */
	case PR_XREGS:	/* no idea... some sort of registers file */
		dprintf(("ptrace: opening an evil file"));
		ptrace_event();
		return (set_errno(ECANCELED));
		break;
	default:
		break;
	}

	dprintf(("ptrace: returning orig_propen()"));
	return orig_propen(vpp, flag, cr);
}

static int
zz_prwrite(vnode_t *vp, uio_t *uiop, int ioflag, struct cred *cr)
{
	prnode_t *pnp = VTOP(vp);

	dprintf(("ptrace: prwrite(%p, %p, %d, %p)", vp, uiop, ioflag, cr));

	switch (pnp->pr_type) {
	case PR_AS:
	case PR_CTL:
	case PR_LWPCTL:
	case PR_XREGS:
		dprintf(("ptrace: writing to an evil file"));
		ptrace_event();
		return (set_errno(ECANCELED));
		break;
	default:
		break;
	}
	return orig_prwrite(vp, uiop, ioflag, cr);
}

static int
ptrace_init(unsigned int id)
{
	vnodeops_t	* vop;


	dprintf(("ptrace: init"));

	set_my_id(id);

	dprintf(("ptrace: setting my_id %d", id));

	if ((prvnodeopsp = (vnodeops_t *) zz_getsym("prvnodeops")) == NULL) {
		zz_printf("");
		return (ENOENT);
	}
	vop = prvnodeopsp;

	dprintf(("ptrace: prvnodeops is %p", vop));

	orig_propen = vop->vop_open;
	orig_prwrite = vop->vop_write;

	dprintf(("ptrace: saving o: %p w: %p", orig_propen, orig_prwrite));

	vop->vop_open = zz_propen;
	vop->vop_write = zz_prwrite;

	dprintf(("ptrace: new o: %p w: %p", vop->vop_open, vop->vop_write));

	return (0);
}

static int
ptrace_fini(void)
{
	vnodeops_t	* vop = prvnodeopsp;

	dprintf(("ptrace: fini"));
	vop->vop_open = orig_propen;
	vop->vop_write = orig_prwrite;

	dprintf(("ptrace: restoring o: %p w: %p",vop->vop_open,vop->vop_write));

	return (0);
}

static void
ptrace_recv(kmsg_t *kp)
{
	return;
}
