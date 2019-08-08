/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_padding.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/05 17:21:40 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 16:27:34 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"
#include <unistd.h>

int			ft_padding(t_ftprintf *env, char **s)
{
	int		len;
	int		total_len;

	len = ft_strlen(*s);
	total_len = ft_predot(env);
	total_len = total_len > len ? total_len : len;
	if (env->pos)
		len = ft_pos_padding(env, s, total_len);
	total_len = total_len > len ? total_len : len;
	env->count += total_len;
	return (total_len);
}
