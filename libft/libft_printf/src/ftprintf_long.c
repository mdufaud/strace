/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printflong.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/04/30 22:47:41 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 17:59:38 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

char				*ftprintf_long(t_ftprintf *env)
{
	long long	num;
	char		*s;

	s = NULL;
	num = va_arg(env->arg, long long);
	if (num < 0)
		env->is_neg = 1;
	s = ft_lltoa(num);
	env->is_num = 1;
	ft_padding(env, &s);
	return (s);
}
