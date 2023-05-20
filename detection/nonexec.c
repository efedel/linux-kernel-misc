#include <kmod.h>

static int non_exec_init(unsigned int id);
static int non_exec_fini(void);
static void non_exec_recv(kmsg_t *kp);

struct zz_kmod non_exec_kmod = {
	non_exec_init,
	non_exec_fini,
	non_exec_recv,
	"NON-EXEC",
	ZZ_VERSION
};

extern int noexec_user_stack, noexec_user_stack_log;

static int
non_exec_init(unsigned int id)
{
	noexec_user_stack = noexec_user_stack_log = 1;
	return (0);
}

static int
non_exec_fini(void)
{
	noexec_user_stack = noexec_user_stack_log = 0;
	return (0);
}

static void
non_exec_recv(kmsg_t *kp)
{
	return;
}
