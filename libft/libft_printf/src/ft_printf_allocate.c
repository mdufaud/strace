/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf_allocate.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/21 16:10:42 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 16:14:21 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

t_ftprintf	*ft_printf_allocate(char *s)
{
	t_ftprintf	*env;

	if (!(env = (t_ftprintf *)malloc(sizeof(t_ftprintf))))
		return (NULL);
	env->s = s;
	env->i = 0;
	env->w = 0;
	env->count = 0;
	env->pos = NULL;
	env->buffer = NULL;
	ft_clearpos(env);
	return (env);
}
