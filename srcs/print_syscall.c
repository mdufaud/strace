#include "ft_strace.h"
#include "syscalls_def.h"

static void			print_syscall_ret_integer(t_trace *trace,
									struct user_regs_struct *regs)
{
	long		ret;
	t_errno		err;

	ret = -regs->rax - 1;
	if (ret >= 0 && ret < 133)
	{
		err = trace->errno[ret];
		printf(" = %s%lld %s (%s)%s\n", PRED, regs->rax + 1, err.name, err.str, PRESET);
	}
	else if ((long)regs->rax <= -512 && (long)regs->rax >= -530)
	{
		err = trace->ker_errno[((long)regs->rax * -1) - 512];
		printf(" = %s%lld %s (%s)%s\n", PRED, regs->rax, err.name, err.str, PRESET);
	}
	else
		printf(" = %s%lld%s\n", (long)regs->rax < 0 ? PRED :PGREEN, regs->rax, PRESET);
}

void				print_syscall_ret(t_trace *trace,
									struct user_regs_struct *regs)
{
	t_syscalls	*sc;

	if (!trace->interactive)
		return ;
	if ((long)regs->orig_rax < 0 || (long)regs->orig_rax > N_SYSCALLS)
	{
		printf(" = ?\n");
		return ;
	}
	sc = trace->syscalls[regs->orig_rax];
	if (sc->args_type[sc->n] == INTEGER)
		print_syscall_ret_integer(trace, regs);
	else if (sc->args_type[sc->n] == POINTER)
		printf("%s = 0x%llx%s\n", PYELLOW, regs->rax, PRESET);
	else if (sc->args_type[sc->n] == VOID)
		printf(" = ?\n");
	else
		printf(" = 0\n");
}

static size_t		print_syscall_args(t_trace *trace,
									struct user_regs_struct *regs)
{
	int			i;
	size_t		size;
	t_syscalls	*sc;

	sc = trace->syscalls[regs->orig_rax];
	size = printf("%s%s%s(", PCYAN, sc->str, PRESET);
	i = 0;
	while (i < sc->n)
	{
		size += print_arg(trace, sc, regs, i);
		i++;
	}
	return (size);
}

void				print_syscall(t_trace *trace,
									struct user_regs_struct *regs)
{
	size_t		size;

	if (!trace->interactive)
		return ;
	if ((int)regs->orig_rax < 0 || (int)regs->orig_rax > N_SYSCALLS)
		size = printf("%sunknown syscall%s(?", PCYAN, PRESET);
	else
		size = print_syscall_args(trace, regs);
	size += printf(")");
	while (size < 39)
	{
		printf(" ");
		size++;
	}
	if (regs->orig_rax == EXIT_GROUP)
		print_syscall_ret(trace, regs);
}
