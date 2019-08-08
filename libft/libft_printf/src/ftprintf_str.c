/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printfstr.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/19 14:46:45 by mdufaud           #+#    #+#             */
/*   Updated: 2016/01/07 17:22:55 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"
#include <unistd.h>

char		*ftprintf_str(t_ftprintf *env)
{
	char	*tmp;
	char	*s;
	int		len;
	int		postdot;

	tmp = va_arg(env->arg, char *);
	if (env->pos && (postdot = ft_postdot(env)))
		len = postdot;
	else
		len = ft_strlen(tmp);
	s = ft_strsub(tmp, 0, len);
	ft_padding(env, &s);
	return (s);
}
