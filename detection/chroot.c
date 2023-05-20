#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/thread.h>

#include <chains.h>
#include <kmod.h>
#include <zzlib.h>

static int chroot_init(unsigned int id);
static int chroot_fini(void);

struct zz_kmod chroot_kmod = {
	chroot_init,
	chroot_fini,
	zz_no_recv,
	"CHROOT",
	ZZ_VERSION
};

static unsigned int	Chroot_Id;
#define	set_my_id(id)	(Chroot_Id = id)
#define	get_my_id()	(Chroot_Id)

static int vuln_calls[] = {
	SYS_chroot,
	SYS_fchroot,
	SYS_mknod,
	SYS_xmknod,
	SYS_mount,
	SYS_modctl
};

#define	MAX_VULN_CALLS	(sizeof(vuln_calls) / sizeof(vuln_calls[0]))

static int
is_chroot(void)
{
	int	ret;

	mutex_enter(&curproc->p_lock);
	ret = u.u_rdir == NULL ? 0 : 1;
	mutex_exit(&curproc->p_lock);

	return (ret);
}

static int64_t
enforce_chroot(void)
{
	if (is_chroot()) {
		kmsg_t	* kp = kmsg_new_event(CHROOT_BREAK);

		if (kp) {
			kp->to = BCOM;
			kp->from = get_my_id();
	
			kmsg_send(kp);
			kmsg_free(kp);
		}
		return set_errno(EPERM);
	}
	return (0);
}

static int
chroot_init(unsigned int id)
{
	int	i;

	set_my_id(id);

	for (i = 0; i < MAX_VULN_CALLS; i++) {
		int	syscall = vuln_calls[i];

		zz_add_link(syscall, enforce_chroot, get_my_id(), BEFORE);
		zz_add_link32(syscall,enforce_chroot, get_my_id(), BEFORE);
	}

	return (0);
}

static int
chroot_fini(void)
{
	int	i;

	for (i = 0; i < MAX_VULN_CALLS; i++) {
		zz_rem_link(vuln_calls[i], get_my_id());
		zz_rem_link32(vuln_calls[i], get_my_id());
	}
	return (0);
}
