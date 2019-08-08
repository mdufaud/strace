/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printfaddr.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/04/30 22:47:41 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 18:15:39 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"
#include <unistd.h>

char				*ftprintf_addr(t_ftprintf *env)
{
	long long		num;
	char			*s;
	char			*tmp;

	s = NULL;
	num = va_arg(env->arg, long long);
	if (num < 0)
		env->is_neg = 1;
	env->is_num = 1;
	tmp = ft_lltoa_base(num, 16);
	s = ft_strjoin("0x", tmp);
	free(tmp);
	ft_padding(env, &s);
	return (s);
}
