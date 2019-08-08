#include "ft_strace.h"
#include "syscalls_def.h"

static int		*init_n_args(int i, int n)
{
	int	*ret;

	if (!(ret = (int *)malloc(sizeof(int) * (n + 1))))
		return (NULL);
	switch (i)
	{
		case READ:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case WRITE:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case OPEN:
			ret[0] = STRING;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case CLOSE:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case STAT:
			ret[0] = STRING;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case FSTAT:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case LSTAT:
			ret[0] = STRING;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case POLL:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case LSEEK:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case MMAP:
			ret[0] = POINTER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
			ret[6] = POINTER;
		break ;
		case MPROTECT:
			ret[0] = POINTER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case MUNMAP:
			ret[0] = POINTER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case BRK:
			ret[0] = POINTER;
			ret[1] = INTEGER;
		break ;
		case SIGACTION:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case SIGPROCMASK:
			ret[0] = INTEGER;
			ret[1] = POINTER;
			ret[2] = POINTER;
			ret[3] = INTEGER;
		break ;
		case SIGRETURN:
			ret[0] = VA_ARG;
			ret[1] = INTEGER;
		break ;
		case IOCTL:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = VA_ARG;
			ret[3] = INTEGER;
		break ;
		case READV:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case WRITEV:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case ACCESS:
			ret[0] = STRING;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case PIPE:
			ret[0] = POINTER;
			ret[1] = INTEGER;
		break ;
		case SELECT:
			ret[0] = INTEGER;
			ret[1] = POINTER;
			ret[2] = POINTER;
			ret[3] = POINTER;
			ret[4] = STRUCTURE;
			ret[5] = INTEGER;
		break ;
		case SCHED_YIELD:
			ret[0] = VOID;
			ret[1] = INTEGER;
		break ;
		case MREMAP:
			ret[0] = POINTER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = POINTER;
			ret[5] = POINTER;
		break ;
		case MSYNC:
			ret[0] = POINTER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case MINCORE:
			ret[0] = POINTER;
			ret[1] = INTEGER;
			ret[2] = STRING;
			ret[3] = INTEGER;
		break ;
		case MADVISE:
			ret[0] = POINTER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case SHMGET:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case SHMAT:
			ret[0] = INTEGER;
			ret[1] = POINTER;
			ret[2] = INTEGER;
			ret[3] = POINTER;
		break ;
		case SHMCTL:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case DUP:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case DUP2:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case PAUSE:
			ret[0] = VOID;
			ret[1] = INTEGER;
		break ;
		case NANOSLEEP:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case GETITIMER:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case ALARM:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case SETITIMER:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case GETPID:
			ret[0] = VOID;
			ret[1] = STRUCTURE;
		break ;
		case SENDFILE:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case SOCKET:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case CONNECT:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case ACCEPT:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = POINTER;
			ret[3] = INTEGER;
		break ;
		case SENDTO:
			ret[0] = INTEGER;
			ret[1] = POINTER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = STRUCTURE;
			ret[5] = STRUCTURE;
			ret[6] = INTEGER;
		break ;
		case RECVFROM:
			ret[0] = INTEGER;
			ret[1] = POINTER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = STRUCTURE;
			ret[5] = POINTER;
			ret[6] = INTEGER;
		break ;
		case SENDMSG:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case RECVMSG:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case SHUTDOWN:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case BIND:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case LISTEN:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case GETSOCKNAME:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = POINTER;
			ret[3] = INTEGER;
		break ;
		case GETPEERNAME:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = POINTER;
			ret[3] = INTEGER;
		break ;
		case SOCKETPAIR:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = POINTER;
			ret[4] = INTEGER;
		break ;
		case SETSOCKOPT:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = POINTER;
			ret[4] = STRUCTURE;
			ret[5] = INTEGER;
		break ;
		case GETSOCKOPT:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = POINTER;
			ret[4] = POINTER;
			ret[5] = INTEGER;
		break ;
		case CLONE:
			ret[0] = INTEGER;
			ret[1] = POINTER;
			ret[2] = INTEGER;
			ret[3] = POINTER;
			ret[4] = POINTER;
			ret[5] = STRUCTURE;
			ret[6] = POINTER;
			ret[7] = INTEGER;
		break ;
		case FORK:
			ret[0] = VOID;
			ret[1] = STRUCTURE;
		break ;
		case VFORK:
			ret[0] = VOID;
			ret[1] = STRUCTURE;
		break ;
		case EXECVE:
			ret[0] = STRING;
			ret[1] = STR_TAB;
			ret[2] = STR_TAB;
			ret[3] = INTEGER;
		break ;
		case EXIT:
			ret[0] = INTEGER;
			ret[1] = VOID;
		break ;
		case WAIT4:
			ret[0] = INTEGER;
			ret[1] = POINTER;
			ret[2] = INTEGER;
			ret[3] = STRUCTURE;
			ret[4] = INTEGER;
		break ;
		case KILL:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case UNAME:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
		break ;
		case SEMGET:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case SEMOP:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case SEMCTL:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = VA_ARG;
			ret[4] = INTEGER;
		break ;
		case SHMDT:
			ret[0] = POINTER;
			ret[1] = INTEGER;
		break ;
		case MSGGET:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case MSGSND:
			ret[0] = INTEGER;
			ret[1] = POINTER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case MSGRCV:
			ret[0] = INTEGER;
			ret[1] = POINTER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
		break ;
		case MSGCTL:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case FCNTL:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = POINTER;
			ret[3] = INTEGER;
		break ;
		case FLOCK:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case FSYNC:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case FDATASYNC:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case TRUNCATE:
			ret[0] = STRING;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case FTRUNCATE:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case GETDENTS:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case GETCWD:
			ret[0] = STRING;
			ret[1] = INTEGER;
			ret[2] = STRING;
		break ;
		case CHDIR:
			ret[0] = STRING;
			ret[1] = INTEGER;
		break ;
		case FCHDIR:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case RENAME:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = INTEGER;
		break ;
		case MKDIR:
			ret[0] = STRING;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case RMDIR:
			ret[0] = STRING;
			ret[1] = INTEGER;
		break ;
		case CREAT:
			ret[0] = STRING;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case LINK:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = INTEGER;
		break ;
		case UNLINK:
			ret[0] = STRING;
			ret[1] = INTEGER;
		break ;
		case SYMLINK:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = INTEGER;
		break ;
		case READLINK:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case CHMOD:
			ret[0] = STRING;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case FCHMOD:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case CHOWN:
			ret[0] = STRING;
			ret[1] = STRUCTURE;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case FCHOWN:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case LCHOWN:
			ret[0] = STRING;
			ret[1] = STRUCTURE;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case UMASK:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
		break ;
		case GETTIMEOFDAY:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case GETRLIMIT:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case GETRUSAGE:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case SYSINFO:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
		break ;
		case TIMES:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
		break ;
		case PTRACE:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = POINTER;
			ret[3] = POINTER;
			ret[4] = INTEGER;
		break ;
		case GETUID:
			ret[0] = INTEGER;
		break ;
		case SYSLOG:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case GETGID:
			ret[0] = INTEGER;
		break ;
		case SETUID:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
		break ;
		case SETGID:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
		break ;
		case GETEUID:
			ret[0] = INTEGER;
		break ;
		case GETEGID:
			ret[0] = INTEGER;
		break ;
		case SETPGID:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case GETPPID:
			ret[0] = VOID;
			ret[1] = STRUCTURE;
		break ;
		case GETPGRP:
			ret[0] = VOID;
			ret[1] = STRUCTURE;
		break ;
		case SETSID:
			ret[0] = VOID;
			ret[1] = STRUCTURE;
		break ;
		case SETREUID:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case SETREGID:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case GETGROUPS:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case SETGROUPS:
			ret[0] = INTEGER;
			ret[1] = POINTER;
			ret[2] = INTEGER;
		break ;
		case SETRESUID:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case GETRESUID:
			ret[0] = POINTER;
			ret[1] = POINTER;
			ret[2] = POINTER;
			ret[3] = INTEGER;
		break ;
		case SETRESGID:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case GETRESGID:
			ret[0] = POINTER;
			ret[1] = POINTER;
			ret[2] = POINTER;
			ret[3] = INTEGER;
		break ;
		case GETPGID:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
		break ;
		case SETFSUID:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case SETFSGID:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case GETSID:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
		break ;
		case CAPGET:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case CAPSET:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case SIGPENDING:
			ret[0] = POINTER;
			ret[1] = INTEGER;
		break ;
		case SIGTIMEDWAIT:
			ret[0] = POINTER;
			ret[1] = POINTER;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case RT_SIGQUEUEINFO:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = POINTER;
			ret[3] = INTEGER;
		break ;
		case SIGSUSPEND:
			ret[0] = POINTER;
			ret[1] = INTEGER;
		break ;
		case SIGALTSTACK:
			ret[0] = POINTER;
			ret[1] = POINTER;
			ret[2] = INTEGER;
		break ;
		case UTIME:
			ret[0] = STRING;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case MKNOD:
			ret[0] = STRING;
			ret[1] = STRUCTURE;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case USELIB:
			ret[0] = STRING;
			ret[1] = INTEGER;
		break ;
		case PERSONALITY:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case USTAT:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case STATFS:
			ret[0] = STRING;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case FSTATFS:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case SYSFS:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
		break ;
		case GETPRIORITY:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case SETPRIORITY:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case SCHED_SETPARAM:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case SCHED_GETPARAM:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case SCHED_SETSCHEDULER:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case SCHED_GETSCHEDULER:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case SCHED_GET_PRIORITY_MAX:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case SCHED_GET_PRIORITY_MIN:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case SCHED_RR_GET_INTERVAL:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case MLOCK:
			ret[0] = POINTER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case MUNLOCK:
			ret[0] = POINTER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case MLOCKALL:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case MUNLOCKALL:
			ret[0] = VOID;
			ret[1] = INTEGER;
		break ;
		case VHANGUP:
			ret[0] = VOID;
			ret[1] = INTEGER;
		break ;
		case MODIFY_LDT:
			ret[0] = INTEGER;
			ret[1] = POINTER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case PIVOT_ROOT:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = INTEGER;
		break ;
		case _SYSCTL:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
		break ;
		case PRCTL:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
		break ;
		case ADJTIMEX:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
		break ;
		case SETRLIMIT:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case CHROOT:
			ret[0] = STRING;
			ret[1] = INTEGER;
		break ;
		case SYNC:
			ret[0] = VOID;
			ret[1] = VOID;
		break ;
		case ACCT:
			ret[0] = STRING;
			ret[1] = INTEGER;
		break ;
		case SETTIMEOFDAY:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case MOUNT:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = STRING;
			ret[3] = INTEGER;
			ret[4] = POINTER;
			ret[5] = INTEGER;
		break ;
		case UMOUNT2:
			ret[0] = STRING;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case SWAPON:
			ret[0] = STRING;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case SWAPOFF:
			ret[0] = STRING;
			ret[1] = INTEGER;
		break ;
		case REBOOT:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = POINTER;
			ret[4] = INTEGER;
		break ;
		case SETHOSTNAME:
			ret[0] = STRING;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case SETDOMAINNAME:
			ret[0] = STRING;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case IOPL:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case IOPERM:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case INIT_MODULE:
			ret[0] = POINTER;
			ret[1] = INTEGER;
			ret[2] = STRING;
			ret[3] = INTEGER;
		break ;
		case RESTART_SYSCALL:
			ret[0] = INTEGER;
		break;
		case QUOTACTL:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = STRUCTURE;
			ret[4] = INTEGER;
		break ;
		case READAHEAD:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case TKILL:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case TIME:
			ret[0] = POINTER;
			ret[1] = STRUCTURE;
		break ;
		case FUTEX:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = STRUCTURE;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
			ret[6] = INTEGER;
		break ;
		case SCHED_SETAFFINITY:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = POINTER;
			ret[3] = INTEGER;
		break ;
		case SCHED_GETAFFINITY:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = POINTER;
			ret[3] = INTEGER;
		break ;
		case SET_THREAD_AREA:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
		break ;
		case IO_SETUP:
			ret[0] = INTEGER;
			ret[1] = POINTER;
			ret[2] = INTEGER;
		break ;
		case IO_DESTROY:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
		break ;
		case IO_GETEVENTS:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = STRUCTURE;
			ret[4] = STRUCTURE;
			ret[5] = INTEGER;
		break ;
		case IO_SUBMIT:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case IO_CANCEL:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case GET_THREAD_AREA:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
		break ;
		case LOOKUP_DCOOKIE:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case EPOLL_CREATE:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case REMAP_FILE_PAGES:
			ret[0] = POINTER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
		break ;
		case SET_TID_ADDRESS:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		break ;
		case SEMTIMEDOP:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = STRUCTURE;
			ret[4] = INTEGER;
		break ;
		case TIMER_CREATE:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = POINTER;
			ret[3] = INTEGER;
		break ;
		case TIMER_SETTIME:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
			ret[2] = STRUCTURE;
			ret[3] = STRUCTURE;
			ret[4] = INTEGER;
		break ;
		case TIMER_GETTIME:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case TIMER_GETOVERRUN:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
		break ;
		case TIMER_DELETE:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
		break ;
		case CLOCK_SETTIME:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case CLOCK_GETTIME:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case GETTID:
			ret[0] = INTEGER;	
		break ;
		case CLOCK_GETRES:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case CLOCK_NANOSLEEP:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
			ret[2] = STRUCTURE;
			ret[3] = STRUCTURE;
			ret[4] = INTEGER;
		break ;
		case EXIT_GROUP:
			ret[0] = INTEGER;
			ret[1] = VOID;
		break ;
		case EPOLL_WAIT:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case EPOLL_CTL:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = STRUCTURE;
			ret[4] = INTEGER;
		break ;
		case TGKILL:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case UTIMES:
			ret[0] = STRING;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case MBIND:
			ret[0] = POINTER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
			ret[6] = INTEGER;
		break ;
		case GET_MEMPOLICY:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
		break ;
		case MQ_OPEN:
			ret[0] = STRING;
			ret[1] = INTEGER;
			ret[2] = STRUCTURE;
		break ;
		case MQ_UNLINK:
			ret[0] = STRING;
			ret[1] = INTEGER;
		break ;
		case MQ_TIMEDSEND:
			ret[0] = STRUCTURE;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = STRUCTURE;
			ret[5] = INTEGER;
		break ;
		case MQ_TIMEDRECEIVE:
			ret[0] = STRUCTURE;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = POINTER;
			ret[4] = STRUCTURE;
			ret[5] = INTEGER;
		break ;
		case MQ_NOTIFY:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case MQ_GETSETATTR:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case KEXEC_LOAD:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case WAITID:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
			ret[2] = POINTER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case ADD_KEY:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = POINTER;
			ret[3] = INTEGER;
			ret[4] = STRUCTURE;
			ret[5] = STRUCTURE;
		break ;
		case REQUEST_KEY:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = STRING;
			ret[3] = STRUCTURE;
			ret[4] = STRUCTURE;
		break ;
		case KEYCTL:
			ret[0] = INTEGER;
			ret[1] = VA_ARG;
			ret[2] = INTEGER;
		break ;
		case IOPRIO_SET:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case IOPRIO_GET:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case INOTIFY_INIT:
			ret[0] = VOID;
			ret[1] = INTEGER;
		break ;
		case INOTIFY_ADD_WATCH:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case INOTIFY_RM_WATCH:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case MIGRATE_PAGES:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case OPENAT:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case MKDIRAT:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case MKNODAT:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = STRUCTURE;
			ret[3] = STRUCTURE;
			ret[4] = INTEGER;
		break ;
		case ARCH_PRCTL:
			ret[0] = INTEGER;
			ret[1] = POINTER;
			ret[2] = INTEGER;
		break ;
		case FCHOWNAT:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = STRUCTURE;
			ret[3] = STRUCTURE;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
		break ;
		case FUTIMESAT:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case UNLINKAT:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case RENAMEAT:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = STRING;
			ret[4] = INTEGER;
		break ;
		case LINKAT:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = STRING;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
		break ;
		case SYMLINKAT:
			ret[0] = STRING;
			ret[1] = INTEGER;
			ret[2] = STRING;
			ret[3] = INTEGER;
		break ;
		case READLINKAT:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = STRING;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case FCHMODAT:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case FACCESSAT:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case PPOLL:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = STRUCTURE;
			ret[3] = POINTER;
			ret[4] = INTEGER;
		break ;
		case UNSHARE:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case SET_ROBUST_LIST:
			ret[0] = STRUCTURE;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case GET_ROBUST_LIST:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = POINTER;
			ret[3] = INTEGER;
		break ;
		case SPLICE:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
			ret[6] = INTEGER;
		break ;
		case TEE:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case SYNC_FILE_RANGE:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case VMSPLICE:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case MOVE_PAGES:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = POINTER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
			ret[6] = INTEGER;
		break ;
		case UTIMENSAT:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case EPOLL_PWAIT:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = POINTER;
			ret[5] = INTEGER;
		break ;
		case TIMERFD_CREATE:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case EVENTFD:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case FALLOCATE:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case TIMERFD_SETTIME:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = STRUCTURE;
			ret[3] = STRUCTURE;
			ret[4] = INTEGER;
		break ;
		case TIMERFD_GETTIME:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		case ACCEPT4:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = POINTER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case EPOLL_CREATE1:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case DUP3:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case PIPE2:
			ret[0] = POINTER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case INOTIFY_INIT1:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case PREADV:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case PWRITEV:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case PERF_EVENT_OPEN:
			ret[0] = STRUCTURE;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
		break ;
		case RECVMMSG:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = STRUCTURE;
			ret[5] = INTEGER;
		break ;
		case PRLIMIT:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = STRUCTURE;
			ret[3] = STRUCTURE;
			ret[4] = INTEGER;
		break ;
		case SYNCFS:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
		break ;
		case SENDMMSG:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case SETNS:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case GETCPU:
			ret[0] = POINTER;
			ret[1] = POINTER;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
		break ;
		case PROCESS_VM_READV:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = STRUCTURE;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
			ret[6] = INTEGER;
		break ;
		case PROCESS_VM_WRITEV:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
			ret[3] = STRUCTURE;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
			ret[6] = INTEGER;
		break ;
		case KCMP:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
		break ;
		case FINIT_MODULE:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case FADVISE64:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
		break ;
		case PREAD64:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case PWRITE64:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case CREATE_MODULE:
			ret[0] = INTEGER;
		break ;
		case DELETE_MODULE:
			ret[0] = STRING;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case GET_KERNEL_SYMS:
			ret[0] = INTEGER;
		break ;
		case QUERY_MODULE:
			ret[0] = INTEGER;
		break ;
		case NFSSERVCTL:
			ret[0] = INTEGER;
		break ;
		case GETPMSG:
			ret[0] = INTEGER;
		break ;
		case PUTPMSG:
			ret[0] = INTEGER;
		break ;
		case AFS_SYSCALL:
			ret[0] = INTEGER;
		break ;
		case TUXCALL:
			ret[0] = INTEGER;
		break ;
		case SECURITY:
			ret[0] = INTEGER;
		break ;
		case SETXATTR:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = POINTER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
		break ;
		case LSETXATTR:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = POINTER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
		break ;
		case FSETXATTR:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = POINTER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
		break ;
		case GETXATTR:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = POINTER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case LGETXATTR:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = POINTER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case FGETXATTR:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = POINTER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case LISTXATTR:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case LLISTXATTR:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case FLISTXATTR:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case REMOVEXATTR:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = INTEGER;
		break ;
		case LREMOVEXATTR:
			ret[0] = STRING;
			ret[1] = STRING;
			ret[2] = INTEGER;
		break ;
		case FREMOVEXATTR:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = INTEGER;
		break ;
		case EPOLL_CTL_OLD:
			ret[0] = INTEGER;
		break ;
		case EPOLL_WAIT_OLD:
			ret[0] = INTEGER;
		break ;
		case VSERVER:
			ret[0] = INTEGER;
		break ;
		case SET_MEMPOLICY:
			ret[0] = INTEGER;
			ret[1] = POINTER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
		break ;
		case NEWFSTATAT:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = STRUCTURE;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
		break ;
		case RT_TGSIGQUEUEINFO:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = STRUCTURE;
			ret[4] = INTEGER;
		break ;
		case FANOTIFY_INIT:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
		break ;
		case FANOTIFY_MARK:
			ret[0] = INTEGER;
			ret[1] = INTEGER;
			ret[2] = INTEGER;
			ret[3] = INTEGER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
		break ;
		case NAME_TO_HANDLE_AT:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = STRUCTURE;
			ret[3] = POINTER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
		break ;
		case OPEN_BY_HANDLE_AT:
			ret[0] = INTEGER;
			ret[1] = STRING;
			ret[2] = STRUCTURE;
			ret[3] = POINTER;
			ret[4] = INTEGER;
			ret[5] = INTEGER;
		break ;
		case CLOCK_ADJTIME:
			ret[0] = INTEGER;
			ret[1] = STRUCTURE;
			ret[2] = INTEGER;
		break ;
		default:
			ret[0] = INTEGER;
	}
	return (ret);
}

static t_syscalls	*get_syscalls(int sys_number)
{
	t_syscalls	*sc;

	if (!(sc = (t_syscalls *)malloc(sizeof(t_syscalls))))
		return (NULL);
	switch (sys_number)
	{
		case READ:
			sc->str = ft_strdup("read");
			sc->n = 3;
		break ;
		case WRITE:
			sc->str = ft_strdup("write");
			sc->n = 3;
		break ;
		case OPEN:
			sc->str = ft_strdup("open");
			sc->n = 2;
		break ;
		case CLOSE:
			sc->str = ft_strdup("close");
			sc->n = 1;
		break ;
		case STAT:
			sc->str = ft_strdup("stat");
			sc->n = 2;
		break ;
		case FSTAT:
			sc->str = ft_strdup("fstat");
			sc->n = 2;
		break ;
		case LSTAT:
			sc->str = ft_strdup("lstat");
			sc->n = 2;
		break ;
		case POLL:
			sc->str = ft_strdup("poll");
			sc->n = 3;
		break ;
		case LSEEK:
			sc->str = ft_strdup("lseek");
			sc->n = 3;
		break ;
		case MMAP:
			sc->str = ft_strdup("mmap");
			sc->n = 6;
		break ;
		case MPROTECT:
			sc->str = ft_strdup("mprotect");
			sc->n = 3;
		break ;
		case MUNMAP:
			sc->str = ft_strdup("munmap");
			sc->n = 2;
		break ;
		case BRK:
			sc->str = ft_strdup("brk");
			sc->n = 1;
		break ;
		case SIGACTION:
			sc->str = ft_strdup("rt_sigaction");
			sc->n = 3;
		break ;
		case SIGPROCMASK:
			sc->str = ft_strdup("rt_sigprocmask");
			sc->n = 3;
		break ;
		case SIGRETURN:
			sc->str = ft_strdup("rt_sigreturn");
			sc->n = 1;
		break ;
		case IOCTL:
			sc->str = ft_strdup("ioctl");
			sc->n = 3;
		break ;
		case READV:
			sc->str = ft_strdup("readv");
			sc->n = 3;
		break ;
		case WRITEV:
			sc->str = ft_strdup("writev");
			sc->n = 3;
		break ;
		case ACCESS:
			sc->str = ft_strdup("access");
			sc->n = 2;
		break ;
		case PIPE:
			sc->str = ft_strdup("pipe");
			sc->n = 1;
		break ;
		case SELECT:
			sc->str = ft_strdup("select");
			sc->n = 5;
		break ;
		case SCHED_YIELD:
			sc->str = ft_strdup("sched_yield");
			sc->n = 1;
		break ;
		case MREMAP:
			sc->str = ft_strdup("mremap");
			sc->n = 5;
		break ;
		case MSYNC:
			sc->str = ft_strdup("msync");
			sc->n = 3;
		break ;
		case MINCORE:
			sc->str = ft_strdup("mincore");
			sc->n = 3;
		break ;
		case MADVISE:
			sc->str = ft_strdup("madvise");
			sc->n = 3;
		break ;
		case SHMGET:
			sc->str = ft_strdup("shmget");
			sc->n = 3;
		break ;
		case SHMAT:
			sc->str = ft_strdup("shmat");
			sc->n = 3;
		break ;
		case SHMCTL:
			sc->str = ft_strdup("shmctl");
			sc->n = 3;
		break ;
		case DUP:
			sc->str = ft_strdup("dup");
			sc->n = 1;
		break ;
		case DUP2:
			sc->str = ft_strdup("dup2");
			sc->n = 2;
		break ;
		case PAUSE:
			sc->str = ft_strdup("pause");
			sc->n = 1;
		break ;
		case NANOSLEEP:
			sc->str = ft_strdup("nanosleep");
			sc->n = 2;
		break ;
		case GETITIMER:
			sc->str = ft_strdup("getitimer");
			sc->n = 2;
		break ;
		case ALARM:
			sc->str = ft_strdup("alarm");
			sc->n = 1;
		break ;
		case SETITIMER:
			sc->str = ft_strdup("setitimer");
			sc->n = 3;
		break ;
		case GETPID:
			sc->str = ft_strdup("getpid");
			sc->n = 1;
		break ;
		case SENDFILE:
			sc->str = ft_strdup("sendfile");
			sc->n = 4;
		break ;
		case SOCKET:
			sc->str = ft_strdup("socket");
			sc->n = 3;
		break ;
		case CONNECT:
			sc->str = ft_strdup("connect");
			sc->n = 3;
		break ;
		case ACCEPT:
			sc->str = ft_strdup("accept");
			sc->n = 3;
		break ;
		case SENDTO:
			sc->str = ft_strdup("sendto");
			sc->n = 6;
		break ;
		case RECVFROM:
			sc->str = ft_strdup("recvfrom");
			sc->n = 6;
		break ;
		case SENDMSG:
			sc->str = ft_strdup("sendmsg");
			sc->n = 3;
		break ;
		case RECVMSG:
			sc->str = ft_strdup("recvmsg");
			sc->n = 3;
		break ;
		case SHUTDOWN:
			sc->str = ft_strdup("shutdown");
			sc->n = 2;
		break ;
		case BIND:
			sc->str = ft_strdup("bind");
			sc->n = 3;
		break ;
		case LISTEN:
			sc->str = ft_strdup("listen");
			sc->n = 2;
		break ;
		case GETSOCKNAME:
			sc->str = ft_strdup("getsockname");
			sc->n = 3;
		break ;
		case GETPEERNAME:
			sc->str = ft_strdup("getpeername");
			sc->n = 3;
		break ;
		case SOCKETPAIR:
			sc->str = ft_strdup("socketpair");
			sc->n = 4;
		break ;
		case SETSOCKOPT:
			sc->str = ft_strdup("setsockopt");
			sc->n = 5;
		break ;
		case GETSOCKOPT:
			sc->str = ft_strdup("getsockopt");
			sc->n = 5;
		break ;
		case CLONE:
			sc->str = ft_strdup("clone");
			sc->n = 7;
		break ;
		case FORK:
			sc->str = ft_strdup("fork");
			sc->n = 1;
		break ;
		case VFORK:
			sc->str = ft_strdup("vfork");
			sc->n = 1;
		break ;
		case EXECVE:
			sc->str = ft_strdup("execve");
			sc->n = 3;
		break ;
		case EXIT:
			sc->str = ft_strdup("exit");
			sc->n = 1;
		break ;
		case WAIT4:
			sc->str = ft_strdup("wait4");
			sc->n = 4;
		break ;
		case KILL:
			sc->str = ft_strdup("kill");
			sc->n = 2;
		break ;
		case UNAME:
			sc->str = ft_strdup("uname");
			sc->n = 1;
		break ;
		case SEMGET:
			sc->str = ft_strdup("semget");
			sc->n = 3;
		break ;
		case SEMOP:
			sc->str = ft_strdup("semop");
			sc->n = 3;
		break ;
		case SEMCTL:
			sc->str = ft_strdup("semctl");
			sc->n = 4;
		break ;
		case SHMDT:
			sc->str = ft_strdup("shmdt");
			sc->n = 1;
		break ;
		case MSGGET:
			sc->str = ft_strdup("msgget");
			sc->n = 2;
		break ;
		case MSGSND:
			sc->str = ft_strdup("msgsnd");
			sc->n = 4;
		break ;
		case MSGRCV:
			sc->str = ft_strdup("msgrcv");
			sc->n = 5;
		break ;
		case MSGCTL:
			sc->str = ft_strdup("msgctl");
			sc->n = 3;
		break ;
		case FCNTL:
			sc->str = ft_strdup("fcntl");
			sc->n = 3;
		break ;
		case FLOCK:
			sc->str = ft_strdup("flock");
			sc->n = 2;
		break ;
		case FSYNC:
			sc->str = ft_strdup("fsync");
			sc->n = 1;
		break ;
		case FDATASYNC:
			sc->str = ft_strdup("fdatasync");
			sc->n = 1;
		break ;
		case TRUNCATE:
			sc->str = ft_strdup("truncate");
			sc->n = 2;
		break ;
		case FTRUNCATE:
			sc->str = ft_strdup("ftruncate");
			sc->n = 2;
		break ;
		case GETDENTS:
			sc->str = ft_strdup("getdents");
			sc->n = 3;
		break ;
		case GETCWD:
			sc->str = ft_strdup("getcwd");
			sc->n = 2;
		break ;
		case CHDIR:
			sc->str = ft_strdup("chdir");
			sc->n = 1;
		break ;
		case FCHDIR:
			sc->str = ft_strdup("fchdir");
			sc->n = 1;
		break ;
		case RENAME:
			sc->str = ft_strdup("rename");
			sc->n = 2;
		break ;
		case MKDIR:
			sc->str = ft_strdup("mkdir");
			sc->n = 2;
		break ;
		case RMDIR:
			sc->str = ft_strdup("rmdir");
			sc->n = 1;
		break ;
		case CREAT:
			sc->str = ft_strdup("creat");
			sc->n = 2;
		break ;
		case LINK:
			sc->str = ft_strdup("link");
			sc->n = 2;
		break ;
		case UNLINK:
			sc->str = ft_strdup("unlink");
			sc->n = 1;
		break ;
		case SYMLINK:
			sc->str = ft_strdup("symlink");
			sc->n = 2;
		break ;
		case READLINK:
			sc->str = ft_strdup("readlink");
			sc->n = 3;
		break ;
		case CHMOD:
			sc->str = ft_strdup("chmod");
			sc->n = 2;
		break ;
		case FCHMOD:
			sc->str = ft_strdup("fchmod");
			sc->n = 2;
		break ;
		case CHOWN:
			sc->str = ft_strdup("chown");
			sc->n = 3;
		break ;
		case FCHOWN:
			sc->str = ft_strdup("fchown");
			sc->n = 3;
		break ;
		case LCHOWN:
			sc->str = ft_strdup("lchown");
			sc->n = 3;
		break ;
		case UMASK:
			sc->str = ft_strdup("umask");
			sc->n = 1;
		break ;
		case GETTIMEOFDAY:
			sc->str = ft_strdup("gettimeofday");
			sc->n = 2;
		break ;
		case GETRLIMIT:
			sc->str = ft_strdup("getrlimit");
			sc->n = 2;
		break ;
		case GETRUSAGE:
			sc->str = ft_strdup("getrusage");
			sc->n = 2;
		break ;
		case SYSINFO:
			sc->str = ft_strdup("sysinfo");
			sc->n = 1;
		break ;
		case TIMES:
			sc->str = ft_strdup("times");
			sc->n = 1;
		break ;
		case PTRACE:
			sc->str = ft_strdup("ptrace");
			sc->n = 4;
		break ;
		case GETUID:
			sc->str = ft_strdup("getuid");
			sc->n = 0;
		break ;
		case SYSLOG:
			sc->str = ft_strdup("syslog");
			sc->n = 3;
		break ;
		case GETGID:
			sc->str = ft_strdup("getgid");
			sc->n = 0;
		break ;
		case SETUID:
			sc->str = ft_strdup("setuid");
			sc->n = 1;
		break ;
		case SETGID:
			sc->str = ft_strdup("setgid");
			sc->n = 1;
		break ;
		case GETEUID:
			sc->str = ft_strdup("geteuid");
			sc->n = 0;
		break ;
		case GETEGID:
			sc->str = ft_strdup("getegid");
			sc->n = 0;
		break ;
		case SETPGID:
			sc->str = ft_strdup("setpgid");
			sc->n = 2;
		break ;
		case GETPPID:
			sc->str = ft_strdup("getppid");
			sc->n = 1;
		break ;
		case GETPGRP:
			sc->str = ft_strdup("getpgrp");
			sc->n = 1;
		break ;
		case SETSID:
			sc->str = ft_strdup("setsid");
			sc->n = 1;
		break ;
		case SETREUID:
			sc->str = ft_strdup("setreuid");
			sc->n = 2;
		break ;
		case SETREGID:
			sc->str = ft_strdup("setregid");
			sc->n = 2;
		break ;
		case GETGROUPS:
			sc->str = ft_strdup("getgroups");
			sc->n = 2;
		break ;
		case SETGROUPS:
			sc->str = ft_strdup("setgroups");
			sc->n = 2;
		break ;
		case SETRESUID:
			sc->str = ft_strdup("setresuid");
			sc->n = 3;
		break ;
		case GETRESUID:
			sc->str = ft_strdup("getresuid");
			sc->n = 3;
		break ;
		case SETRESGID:
			sc->str = ft_strdup("setresgid");
			sc->n = 3;
		break ;
		case GETRESGID:
			sc->str = ft_strdup("getresgid");
			sc->n = 3;
		break ;
		case GETPGID:
			sc->str = ft_strdup("getpgid");
			sc->n = 1;
		break ;
		case SETFSUID:
			sc->str = ft_strdup("setfsuid");
			sc->n = 1;
		break ;
		case SETFSGID:
			sc->str = ft_strdup("setfsgid");
			sc->n = 1;
		break ;
		case GETSID:
			sc->str = ft_strdup("getsid");
			sc->n = 1;
		break ;
		case CAPGET:
			sc->str = ft_strdup("capget");
			sc->n = 2;
		break ;
		case CAPSET:
			sc->str = ft_strdup("capset");
			sc->n = 2;
		break ;
		case SIGPENDING:
			sc->str = ft_strdup("rt_sigpending");
			sc->n = 1;
		break ;
		case SIGTIMEDWAIT:
			sc->str = ft_strdup("rt_sigtimedwait");
			sc->n = 3;
		break ;
		case RT_SIGQUEUEINFO:
			sc->str = ft_strdup("rt_sigqueueinfo");
			sc->n = 3;
		break ;
		case SIGSUSPEND:
			sc->str = ft_strdup("rt_sigsuspend");
			sc->n = 1;
		break ;
		case SIGALTSTACK:
			sc->str = ft_strdup("sigaltstack");
			sc->n = 2;
		break ;
		case UTIME:
			sc->str = ft_strdup("utime");
			sc->n = 2;
		break ;
		case MKNOD:
			sc->str = ft_strdup("mknod");
			sc->n = 3;
		break ;
		case USELIB:
			sc->str = ft_strdup("uselib");
			sc->n = 1;
		break ;
		case PERSONALITY:
			sc->str = ft_strdup("personality");
			sc->n = 1;
		break ;
		case USTAT:
			sc->str = ft_strdup("ustat");
			sc->n = 2;
		break ;
		case STATFS:
			sc->str = ft_strdup("statfs");
			sc->n = 2;
		break ;
		case FSTATFS:
			sc->str = ft_strdup("fstatfs");
			sc->n = 2;
		break ;
		case SYSFS:
			sc->str = ft_strdup("sysfs");
			sc->n = 2;
		break ;
		case GETPRIORITY:
			sc->str = ft_strdup("getpriority");
			sc->n = 2;
		break ;
		case SETPRIORITY:
			sc->str = ft_strdup("setpriority");
			sc->n = 3;
		break ;
		case SCHED_SETPARAM:
			sc->str = ft_strdup("sched_setparam");
			sc->n = 2;
		break ;
		case SCHED_GETPARAM:
			sc->str = ft_strdup("sched_getparam");
			sc->n = 2;
		break ;
		case SCHED_SETSCHEDULER:
			sc->str = ft_strdup("sched_setscheduler");
			sc->n = 3;
		break ;
		case SCHED_GETSCHEDULER:
			sc->str = ft_strdup("sched_getscheduler");
			sc->n = 1;
		break ;
		case SCHED_GET_PRIORITY_MAX:
			sc->str = ft_strdup("sched_get_priority_max");
			sc->n = 1;
		break ;
		case SCHED_GET_PRIORITY_MIN:
			sc->str = ft_strdup("sched_get_priority_min");
			sc->n = 1;
		break ;
		case SCHED_RR_GET_INTERVAL:
			sc->str = ft_strdup("sched_rr_get_interval");
			sc->n = 2;
		break ;
		case MLOCK:
			sc->str = ft_strdup("mlock");
			sc->n = 2;
		break ;
		case MUNLOCK:
			sc->str = ft_strdup("munlock");
			sc->n = 2;
		break ;
		case MLOCKALL:
			sc->str = ft_strdup("mlockall");
			sc->n = 1;
		break ;
		case MUNLOCKALL:
			sc->str = ft_strdup("munlockall");
			sc->n = 1;
		break ;
		case VHANGUP:
			sc->str = ft_strdup("vhangup");
			sc->n = 1;
		break ;
		case MODIFY_LDT:
			sc->str = ft_strdup("modify_ldt");
			sc->n = 3;
		break ;
		case PIVOT_ROOT:
			sc->str = ft_strdup("pivot_root");
			sc->n = 2;
		break ;
		case _SYSCTL:
			sc->str = ft_strdup("_sysctl");
			sc->n = 1;
		break ;
		case PRCTL:
			sc->str = ft_strdup("prctl");
			sc->n = 5;
		break ;
		case ARCH_PRCTL:
			sc->str = ft_strdup("arch_prctl");
			sc->n = 2;
		break ;
		case ADJTIMEX:
			sc->str = ft_strdup("adjtimex");
			sc->n = 1;
		break ;
		case SETRLIMIT:
			sc->str = ft_strdup("setrlimit");
			sc->n = 2;
		break ;
		case CHROOT:
			sc->str = ft_strdup("chroot");
			sc->n = 1;
		break ;
		case SYNC:
			sc->str = ft_strdup("sync");
			sc->n = 1;
		break ;
		case ACCT:
			sc->str = ft_strdup("acct");
			sc->n = 1;
		break ;
		case SETTIMEOFDAY:
			sc->str = ft_strdup("settimeofday");
			sc->n = 2;
		break ;
		case MOUNT:
			sc->str = ft_strdup("mount");
			sc->n = 5;
		break ;
		case UMOUNT2:
			sc->str = ft_strdup("umount2");
			sc->n = 2;
		break ;
		case SWAPON:
			sc->str = ft_strdup("swapon");
			sc->n = 2;
		break ;
		case SWAPOFF:
			sc->str = ft_strdup("swapoff");
			sc->n = 1;
		break ;
		case REBOOT:
			sc->str = ft_strdup("reboot");
			sc->n = 4;
		break ;
		case SETHOSTNAME:
			sc->str = ft_strdup("sethostname");
			sc->n = 2;
		break ;
		case SETDOMAINNAME:
			sc->str = ft_strdup("setdomainname");
			sc->n = 2;
		break ;
		case IOPL:
			sc->str = ft_strdup("iopl");
			sc->n = 1;
		break ;
		case IOPERM:
			sc->str = ft_strdup("ioperm");
			sc->n = 3;
		break ;
		case INIT_MODULE:
			sc->str = ft_strdup("init_module");
			sc->n = 3;
		break ;
		case QUOTACTL:
			sc->str = ft_strdup("quotactl");
			sc->n = 4;
		break ;
		case GETTID:
			sc->str = ft_strdup("gettid");
			sc->n = 0;
		break ;
		case READAHEAD:
			sc->str = ft_strdup("readahead");
			sc->n = 3;
		break ;
		case TKILL:
			sc->str = ft_strdup("tkill");
			sc->n = 2;
		break ;
		case TIME:
			sc->str = ft_strdup("time");
			sc->n = 1;
		break ;
		case FUTEX:
			sc->str = ft_strdup("futex");
			sc->n = 6;
		break ;
		case SCHED_SETAFFINITY:
			sc->str = ft_strdup("sched_setaffinity");
			sc->n = 3;
		break ;
		case SCHED_GETAFFINITY:
			sc->str = ft_strdup("sched_getaffinity");
			sc->n = 3;
		break ;
		case SET_THREAD_AREA:
			sc->str = ft_strdup("set_thread_area");
			sc->n = 1;
		break ;
		case IO_SETUP:
			sc->str = ft_strdup("io_setup");
			sc->n = 2;
		break ;
		case IO_DESTROY:
			sc->str = ft_strdup("io_destroy");
			sc->n = 1;
		break ;
		case RESTART_SYSCALL:
			sc->str = ft_strdup("restart_syscalls");
			sc->n = 0;
		break ;
		case IO_GETEVENTS:
			sc->str = ft_strdup("io_getevents");
			sc->n = 5;
		break ;
		case IO_SUBMIT:
			sc->str = ft_strdup("io_submit");
			sc->n = 3;
		break ;
		case IO_CANCEL:
			sc->str = ft_strdup("io_cancel");
			sc->n = 3;
		break ;
		case GET_THREAD_AREA:
			sc->str = ft_strdup("get_thread_area");
			sc->n = 1;
		break ;
		case LOOKUP_DCOOKIE:
			sc->str = ft_strdup("lookup_dcookie");
			sc->n = 3;
		break ;
		case EPOLL_CREATE:
			sc->str = ft_strdup("epoll_create");
			sc->n = 1;
		break ;
		case REMAP_FILE_PAGES:
			sc->str = ft_strdup("remap_file_pages");
			sc->n = 5;
		break ;
		case GETDENTS64:
			sc->str = ft_strdup("getdents64");
			sc->n = 3;
		break ;
		case SET_TID_ADDRESS:
			sc->str = ft_strdup("set_tid_address");
			sc->n = 1;
		break ;
		case SEMTIMEDOP:
			sc->str = ft_strdup("semtimedop");
			sc->n = 4;
		break ;
		case FADVISE64:
			sc->str = ft_strdup("fadvise64");
			sc->n = 4;
		break ;
		case TIMER_CREATE:
			sc->str = ft_strdup("timer_create");
			sc->n = 3;
		break ;
		case TIMER_SETTIME:
			sc->str = ft_strdup("timer_settime");
			sc->n = 4;
		break ;
		case TIMER_GETTIME:
			sc->str = ft_strdup("timer_gettime");
			sc->n = 2;
		break ;
		case TIMER_GETOVERRUN:
			sc->str = ft_strdup("timer_getoverrun");
			sc->n = 1;
		break ;
		case TIMER_DELETE:
			sc->str = ft_strdup("timer_delete");
			sc->n = 1;
		break ;
		case CLOCK_SETTIME:
			sc->str = ft_strdup("clock_settime");
			sc->n = 2;
		break ;
		case CLOCK_GETTIME:
			sc->str = ft_strdup("clock_gettime");
			sc->n = 2;
		break ;
		case CLOCK_GETRES:
			sc->str = ft_strdup("clock_getres");
			sc->n = 2;
		break ;
		case CLOCK_NANOSLEEP:
			sc->str = ft_strdup("clock_nanosleep");
			sc->n = 4;
		break ;
		case EXIT_GROUP:
			sc->str = ft_strdup("exit_group");
			sc->n = 1;
		break ;
		case EPOLL_WAIT:
			sc->str = ft_strdup("epoll_wait");
			sc->n = 4;
		break ;
		case EPOLL_CTL:
			sc->str = ft_strdup("epoll_ctl");
			sc->n = 4;
		break ;
		case TGKILL:
			sc->str = ft_strdup("tgkill");
			sc->n = 3;
		break ;
		case UTIMES:
			sc->str = ft_strdup("utimes");
			sc->n = 2;
		break ;
		case MBIND:
			sc->str = ft_strdup("mbind");
			sc->n = 6;
		break ;
		case GET_MEMPOLICY:
			sc->str = ft_strdup("get_mempolicy");
			sc->n = 5;
		break ;
		case MQ_OPEN:
			sc->str = ft_strdup("mq_open");
			sc->n = 2;
		break ;
		case MQ_UNLINK:
			sc->str = ft_strdup("mq_unlink");
			sc->n = 1;
		break ;
		case MQ_TIMEDSEND:
			sc->str = ft_strdup("mq_timedsend");
			sc->n = 5;
		break ;
		case MQ_TIMEDRECEIVE:
			sc->str = ft_strdup("mq_timedreceive");
			sc->n = 5;
		break ;
		case MQ_NOTIFY:
			sc->str = ft_strdup("mq_notify");
			sc->n = 2;
		break ;
		case MQ_GETSETATTR:
			sc->str = ft_strdup("mq_getsetattr");
			sc->n = 3;
		break ;
		case KEXEC_LOAD:
			sc->str = ft_strdup("kexec_load");
			sc->n = 4;
		break ;
		case WAITID:
			sc->str = ft_strdup("waitid");
			sc->n = 4;
		break ;
		case ADD_KEY:
			sc->str = ft_strdup("add_key");
			sc->n = 5;
		break ;
		case REQUEST_KEY:
			sc->str = ft_strdup("request_key");
			sc->n = 4;
		break ;
		case KEYCTL:
			sc->str = ft_strdup("keyctl");
			sc->n = 2;
		break ;
		case IOPRIO_SET:
			sc->str = ft_strdup("ioprio_set");
			sc->n = 3;
		break ;
		case IOPRIO_GET:
			sc->str = ft_strdup("ioprio_get");
			sc->n = 2;
		break ;
		case INOTIFY_INIT:
			sc->str = ft_strdup("inotify_init");
			sc->n = 1;
		break ;
		case INOTIFY_ADD_WATCH:
			sc->str = ft_strdup("inotify_add_watch");
			sc->n = 3;
		break ;
		case INOTIFY_RM_WATCH:
			sc->str = ft_strdup("inotify_rm_watch");
			sc->n = 2;
		break ;
		case MIGRATE_PAGES:
			sc->str = ft_strdup("migrate_pages");
			sc->n = 4;
		break ;
		case OPENAT:
			sc->str = ft_strdup("openat");
			sc->n = 3;
		break ;
		case MKDIRAT:
			sc->str = ft_strdup("mkdirat");
			sc->n = 3;
		break ;
		case MKNODAT:
			sc->str = ft_strdup("mknodat");
			sc->n = 4;
		break ;
		case FCHOWNAT:
			sc->str = ft_strdup("fchownat");
			sc->n = 5;
		break ;
		case FUTIMESAT:
			sc->str = ft_strdup("futimesat");
			sc->n = 3;
		break ;
		case UNLINKAT:
			sc->str = ft_strdup("unlinkat");
			sc->n = 3;
		break ;
		case RENAMEAT:
			sc->str = ft_strdup("renameat");
			sc->n = 4;
		break ;
		case LINKAT:
			sc->str = ft_strdup("linkat");
			sc->n = 5;
		break ;
		case SYMLINKAT:
			sc->str = ft_strdup("symlinkat");
			sc->n = 3;
		break ;
		case READLINKAT:
			sc->str = ft_strdup("readlinkat");
			sc->n = 4;
		break ;
		case FCHMODAT:
			sc->str = ft_strdup("fchmodat");
			sc->n = 4;
		break ;
		case FACCESSAT:
			sc->str = ft_strdup("faccessat");
			sc->n = 4;
		break ;
		case PSELECT6:
			sc->str = ft_strdup("pselect6");
			sc->n = 3;
		break ;
		case PPOLL:
			sc->str = ft_strdup("ppoll");
			sc->n = 4;
		break ;
		case UNSHARE:
			sc->str = ft_strdup("unshare");
			sc->n = 1;
		break ;
		case SET_ROBUST_LIST:
			sc->str = ft_strdup("set_robust_list");
			sc->n = 2;
		break ;
		case GET_ROBUST_LIST:
			sc->str = ft_strdup("get_robust_list");
			sc->n = 3;
		break ;
		case SPLICE:
			sc->str = ft_strdup("splice");
			sc->n = 6;
		break ;
		case TEE:
			sc->str = ft_strdup("tee");
			sc->n = 4;
		break ;
		case SYNC_FILE_RANGE:
			sc->str = ft_strdup("sync_file_range");
			sc->n = 4;
		break ;
		case VMSPLICE:
			sc->str = ft_strdup("vmsplice");
			sc->n = 4;
		break ;
		case MOVE_PAGES:
			sc->str = ft_strdup("move_pages");
			sc->n = 6;
		break ;
		case UTIMENSAT:
			sc->str = ft_strdup("utimensat");
			sc->n = 4;
		break ;
		case EPOLL_PWAIT:
			sc->str = ft_strdup("epoll_pwait");
			sc->n = 5;
		break ;
		case SIGNALFD:
			sc->str = ft_strdup("signalfd");
			sc->n = 3;
		break ;
		case TIMERFD_CREATE:
			sc->str = ft_strdup("timerfd_create");
			sc->n = 2;
		break ;
		case EVENTFD:
			sc->str = ft_strdup("eventfd");
			sc->n = 2;
		break ;
		case FALLOCATE:
			sc->str = ft_strdup("fallocate");
			sc->n = 4;
		break ;
		case TIMERFD_SETTIME:
			sc->str = ft_strdup("timerfd_settime");
			sc->n = 4;
		break ;
		case TIMERFD_GETTIME:
			sc->str = ft_strdup("timerfd_gettime");
			sc->n = 2;
		break ;
		case ACCEPT4:
			sc->str = ft_strdup("accept4");
			sc->n = 4;
		break ;
		case SIGNALFD4:
			sc->str = ft_strdup("signalfd4");
			sc->n = 9;
		break ;
		case EVENTFD2:
			sc->str = ft_strdup("eventfd2");
			sc->n = 14;
		break ;
		case EPOLL_CREATE1:
			sc->str = ft_strdup("epoll_create1");
			sc->n = 1;
		break ;
		case DUP3:
			sc->str = ft_strdup("dup3");
			sc->n = 3;
		break ;
		case PIPE2:
			sc->str = ft_strdup("pipe2");
			sc->n = 2;
		break ;
		case INOTIFY_INIT1:
			sc->str = ft_strdup("inotify_init1");
			sc->n = 1;
		break ;
		case PREADV:
			sc->str = ft_strdup("preadv");
			sc->n = 4;
		break ;
		case PWRITEV:
			sc->str = ft_strdup("pwritev");
			sc->n = 4;
		break ;
		case PERF_EVENT_OPEN:
			sc->str = ft_strdup("perf_event_open");
			sc->n = 5;
		break ;
		case RECVMMSG:
			sc->str = ft_strdup("recvmmsg");
			sc->n = 5;
		break ;
		case PRLIMIT:
			sc->str = ft_strdup("prlimit");
			sc->n = 4;
		break ;
		case SYNCFS:
			sc->str = ft_strdup("syncfs");
			sc->n = 1;
		break ;
		case SENDMMSG:
			sc->str = ft_strdup("sendmmsg");
			sc->n = 4;
		break ;
		case SETNS:
			sc->str = ft_strdup("setns");
			sc->n = 2;
		break ;
		case GETCPU:
			sc->str = ft_strdup("getcpu");
			sc->n = 3;
		break ;
		case PROCESS_VM_READV:
			sc->str = ft_strdup("process_vm_readv");
			sc->n = 6;
		break ;
		case PROCESS_VM_WRITEV:
			sc->str = ft_strdup("process_vm_writev");
			sc->n = 6;
		break ;
		case KCMP:
			sc->str = ft_strdup("kcmp");
			sc->n = 5;
		break ;
		case FINIT_MODULE:
			sc->str = ft_strdup("finit_module");
			sc->n = 3;
		break ;
		case PREAD64:
			sc->str = ft_strdup("pread64");
			sc->n = 4;
		break ;
		case PWRITE64:
			sc->str = ft_strdup("pwrite64");
			sc->n = 4;
		break ;
		case CREATE_MODULE:
			sc->str = ft_strdup("create_module");
			sc->n = 0;
		break ;
		case DELETE_MODULE:
			sc->str = ft_strdup("delete_module");
			sc->n = 2;
		break ;
		case GET_KERNEL_SYMS:
			sc->str = ft_strdup("get_kernel_syms");
			sc->n = 0;
		break ;
		case QUERY_MODULE:
			sc->str = ft_strdup("query_module");
			sc->n = 0;
		break ;
		case NFSSERVCTL:
			sc->str = ft_strdup("nfsservctl");
			sc->n = 0;
		break ;
		case GETPMSG:
			sc->str = ft_strdup("getpmsg");
			sc->n = 0;
		break ;
		case PUTPMSG:
			sc->str = ft_strdup("putpmsg");
			sc->n = 0;
		break ;
		case AFS_SYSCALL:
			sc->str = ft_strdup("afs_syscall");
			sc->n = 0;
		break ;
		case TUXCALL:
			sc->str = ft_strdup("tuxcall");
			sc->n = 0;
		break ;
		case SECURITY:
			sc->str = ft_strdup("security");
			sc->n = 0;
		break ;
		case SETXATTR:
			sc->str = ft_strdup("setxattr");
			sc->n = 5;
		break ;
		case LSETXATTR:
			sc->str = ft_strdup("lsetxattr");
			sc->n = 5;
		break ;
		case FSETXATTR:
			sc->str = ft_strdup("fsetxattr");
			sc->n = 5;
		break ;
		case GETXATTR:
			sc->str = ft_strdup("getxattr");
			sc->n = 4;
		break ;
		case LGETXATTR:
			sc->str = ft_strdup("lgetxattr");
			sc->n = 4;
		break ;
		case FGETXATTR:
			sc->str = ft_strdup("fgetxattr");
			sc->n = 4;
		break ;
		case LISTXATTR:
			sc->str = ft_strdup("listxattr");
			sc->n = 3;
		break ;
		case LLISTXATTR:
			sc->str = ft_strdup("llistxattr");
			sc->n = 3;
		break ;
		case FLISTXATTR:
			sc->str = ft_strdup("flistxattr");
			sc->n = 3;
		break ;
		case REMOVEXATTR:
			sc->str = ft_strdup("removexattr");
			sc->n = 2;
		break ;
		case LREMOVEXATTR:
			sc->str = ft_strdup("lremovexattr");
			sc->n = 2;
		break ;
		case FREMOVEXATTR:
			sc->str = ft_strdup("fremovexattr");
			sc->n = 2;
		break ;
		case EPOLL_CTL_OLD:
			sc->str = ft_strdup("epoll_ctl_old");
			sc->n = 0;
		break ;
		case EPOLL_WAIT_OLD:
			sc->str = ft_strdup("epoll_wait_old");
			sc->n = 0;
		break ;
		case VSERVER:
			sc->str = ft_strdup("vserver");
			sc->n = 0;
		break ;
		case SET_MEMPOLICY:
			sc->str = ft_strdup("set_mempolicy");
			sc->n = 3;
		break ;
		case NEWFSTATAT:
			sc->str = ft_strdup("newfstatat");
			sc->n = 4;
		break ;
		case RT_TGSIGQUEUEINFO:
			sc->str = ft_strdup("rt_tgsigqueueinfo");
			sc->n = 4;
		break ;
		case FANOTIFY_INIT:
			sc->str = ft_strdup("fanotify_init");
			sc->n = 2;
		break ;
		case FANOTIFY_MARK:
			sc->str = ft_strdup("fanotify_mark");
			sc->n = 5;
		break ;
		case NAME_TO_HANDLE_AT:
			sc->str = ft_strdup("name_to_handle_at");
			sc->n = 5;
		break ;
		case OPEN_BY_HANDLE_AT:
			sc->str = ft_strdup("open_by_handle_at");
			sc->n = 5;
		break ;
		case CLOCK_ADJTIME:
			sc->str = ft_strdup("clock_adjtime");
			sc->n = 2;
		break ;
		default:
			sc->str = ft_strdup("unknown syscall");
			sc->n = 0;
	}
	sc->args_type = init_n_args(sys_number, sc->n + 1);
	return (sc);
}

t_syscalls	**prepare_syscalls(void)
{
	int			i;
	t_syscalls	**tab;

	i = 0;
	if (!(tab = (t_syscalls **)malloc(sizeof(t_syscalls *) * (N_SYSCALLS + 1))))
		return (NULL);
	while (i < N_SYSCALLS)
	{
		if (!(tab[i] = get_syscalls(i)))
			return (NULL);
		i++;
	}
	tab[i] = NULL;
	return (tab);
}
