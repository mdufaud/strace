#include <signal.h>
#include <stdio.h>

char		*get_signame(int sig)
{
	if (sig == SIGHUP)
		return ("SIGHUP");
	if (sig == SIGINT)
		return ("SIGINT");
	if (sig == SIGQUIT)
		return ("SIGQUIT");
	if (sig == SIGILL)
		return ("SIGILL");
	if (sig == SIGTRAP)
		return ("SIGTRAP");
	if (sig == SIGABRT)
		return ("SIGABRT");
	if (sig == SIGBUS)
		return ("SIGBUS");
	if (sig == SIGFPE)
		return ("SIGFPE");
	if (sig == SIGKILL)
		return ("SIGKILL");
	if (sig == SIGUSR1)
		return ("SIGUSR1");
	if (sig == SIGSEGV)
		return ("SIGSEGV");
	if (sig == SIGUSR2)
		return ("SIGUSR2");
	if (sig == SIGPIPE)
		return ("SIGPIPE");
	if (sig == SIGALRM)
		return ("SIGALRM");
	if (sig == SIGTERM)
		return ("SIGTERM");
	if (sig == SIGSTKFLT)
		return ("SIGSTKFLT");
	if (sig == SIGCHLD)
		return ("SIGCHLD");
	if (sig == SIGCONT)
		return ("SIGCONT");
	if (sig == SIGSTOP)
		return ("SIGSTOP");
	if (sig == SIGTSTP)
		return ("SIGTSTP");
	if (sig == SIGTTIN)
		return ("SIGTTIN");
	if (sig == SIGTTOU)
		return ("SIGTTOU");
	if (sig == SIGURG)
		return ("SIGURG");
	if (sig == SIGXCPU)
		return ("SIGXCPU");
	if (sig == SIGXFSZ)
		return ("SIGXFSZ");
	if (sig == SIGVTALRM)
		return ("SIGVTALRM");
	if (sig == SIGPROF)
		return ("SIGPROF");
	if (sig == SIGWINCH)
		return ("SIGWINCH");
	if (sig == SIGPOLL)
		return ("SIGPOLL");
	if (sig == SIGPWR)
		return ("SIGPWR");
	if (sig == SIGSYS)
		return ("SIGSYS");
	if (sig == SIGPROF)
		return ("SIGPROF");
	return ("unknown signal");
}
