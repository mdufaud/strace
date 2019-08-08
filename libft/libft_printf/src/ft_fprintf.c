/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_fprintf.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/22 15:38:02 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/22 16:05:55 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"
#include <unistd.h>

int				ft_fprintf(int fd, char *format, ...)
{
	t_ftprintf	*env;
	int			count;

	if (!(env = ft_printf_allocate(format)))
		return (-1);
	va_start(env->arg, format);
	ft_parse_printf(env);
	ft_putstr_fd(env->buffer, fd);
	free(env->buffer);
	va_end(env->arg);
	count = env->count;
	free(env);
	return (count);
}
