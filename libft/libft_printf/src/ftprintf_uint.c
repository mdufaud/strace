/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printfuint.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/04/30 22:47:41 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 14:24:20 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

char	*ftprintf_uint(t_ftprintf *env)
{
	unsigned long long		u;
	char					*s;

	u = 0;
	u = (unsigned int)va_arg(env->arg, unsigned long long);
	s = ft_uitoa(u);
	env->is_num = 1;
	env->is_unsigned = 1;
	ft_padding(env, &s);
	return (s);
}
