/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printuntil.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/19 14:46:45 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 16:08:41 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"
#include <unistd.h>

void	ft_printuntil(t_ftprintf *env)
{
	char	*sub;

	sub = ft_strsub(env->s, env->w, env->i - env->w);
	if (!env->buffer)
		env->buffer = sub;
	else
	{
		env->buffer = ft_strjoin_free(&env->buffer, sub);
		free(sub);
	}
	env->w += env->i - env->w;
}
