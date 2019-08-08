/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printfoct.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/12/22 19:06:02 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 18:17:55 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"
#include <unistd.h>

char				*ftprintf_oct(t_ftprintf *env)
{
	unsigned long	num;
	char			*s;

	s = NULL;
	num = va_arg(env->arg, unsigned long);
	s = ft_ultoa_base(num, 8);
	env->is_num = 1;
	ft_padding(env, &s);
	return (s);
}
