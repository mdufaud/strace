/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_getarg.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/07 21:39:53 by mdufaud           #+#    #+#             */
/*   Updated: 2016/01/07 22:46:33 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

long long		ft_getarg(t_ftprintf *env)
{
	if (env->size_flag & HH_VALUE)
		return ((signed char)va_arg(env->arg, int));
	else if (env->size_flag & H_VALUE)
		return ((short int)va_arg(env->arg, int));
	else if (env->size_flag & LL_VALUE)
		return (va_arg(env->arg, long long int));
	else if (env->size_flag & L_VALUE)
		return (va_arg(env->arg, long int));
	else if (env->size_flag & J_VALUE)
		return (va_arg(env->arg, intmax_t));
	else if (env->size_flag & Z_VALUE)
		return (va_arg(env->arg, size_t));
	return (va_arg(env->arg, int));
}
