/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_sprintf.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/21 16:15:11 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 16:15:50 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"
#include <unistd.h>

int				ft_sprintf(char **s, char *format, ...)
{
	t_ftprintf	*env;
	int			count;

	if (!(env = ft_printf_allocate(format)))
		return (-1);
	va_start(env->arg, format);
	ft_parse_printf(env);
	*s = env->buffer;
	va_end(env->arg);
	count = env->count;
	free(env);
	return (count);
}
