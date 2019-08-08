/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printfcolor.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/04/26 14:21:03 by mdufaud           #+#    #+#             */
/*   Updated: 2014/04/26 15:03:41 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

int		ftprintf_color(t_ftprintf *env, int arg_size)
{
	t_color	color;

	color = va_arg(env->arg, t_color);
	if (color == end_color || env->active_color)
	{
		ftprintf_end_color();
		env->active_color = 0;
	}
	if (color != end_color)
	{
		ftprintf_put_color(color);
		env->w += arg_size;
		env->i += arg_size;
		env->active_color = 1;
	}
	return (1);
}
