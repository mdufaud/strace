/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_pre_padding.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/21 16:19:39 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 16:20:33 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

char		*ft_pre_padding(t_ftprintf *env, char *s,
								int total_size, int num_size)
{
	char	*chars;
	char	*tmp;

	tmp = 0;
	if (env->is_0 && !ft_postdot(env) && UNIX_STR_CONDITION)
		chars = ft_get_x_char('0', total_size - num_size);
	else
		chars = ft_get_x_char(' ', total_size - num_size);
	if (!chars)
		return (ft_strdup(s));
	if (env->is_less)
		tmp = ft_strjoin(s, chars);
	else
		tmp = ft_strjoin(chars, s);
	free(chars);
	return (tmp);
}
