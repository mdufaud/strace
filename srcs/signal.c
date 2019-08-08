#include "ft_strace.h"
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

void	sig_handler(int sig)
{
	int		stop;

	if (WIFSIGNALED(sig))
	{
		stop = WTERMSIG(sig);
		(void)stop;
		printf("ft_strace: process %d detached\n", get_trace(NULL)->child);
		if (!get_trace(NULL)->interactive)
			print_stat(get_trace(NULL));
		if (get_trace(NULL)
				&& ptrace(PTRACE_DETACH, get_trace(NULL)->child, NULL, NULL) >= 0)
		{
			printf("<detached ...>\n");
			exit(0);
		}
		exit(1);
	}
}

void	add_sig_handler(void)
{
	struct   sigaction sact;

	sigemptyset(&sact.sa_mask);
	sact.sa_flags = 0;
	sact.sa_handler = &sig_handler;
	sigaction(SIGINT, &sact, NULL);
	sigaction(SIGTERM, &sact, NULL);
	sigaction(SIGHUP, &sact, NULL);
	sigaction(SIGQUIT, &sact, NULL);
	sigaction(SIGPIPE, &sact, NULL);
}

void	add_sig(void)
{
	sigset_t	sigset;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGHUP);
	sigaddset(&sigset, SIGQUIT);
	sigaddset(&sigset, SIGPIPE);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
}

void	remove_sig(void)
{
	sigset_t	sigset;

	sigemptyset(&sigset);
	sigprocmask(SIG_SETMASK, &sigset, NULL);
}

void	print_siginfo(t_trace *trace)
{
	char		*name;
	siginfo_t	si;

	if (ptrace(PTRACE_GETSIGINFO, trace->child, NULL, &si) < 0)
		return ;
	trace->sig = si.si_signo;
	if (!trace->interactive)
		return ;
	name = get_signame(si.si_signo);
	printf("--- %s {si_signo=%d, si_code=%d, si_pid=%d, "
			"si_uid=%d} ---\n",
			name, si.si_signo, si.si_code, si.si_pid,
			si.si_uid);
}
