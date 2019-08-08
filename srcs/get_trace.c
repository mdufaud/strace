#include "ft_strace.h"

t_trace	*get_trace(t_trace *trace)
{
	static t_trace	*ret = NULL;

	if (!ret && trace)
		ret = trace;
	return (ret);
}
