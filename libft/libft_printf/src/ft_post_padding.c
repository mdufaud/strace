/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_post_padding.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/21 16:19:36 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 16:29:12 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

char		*ft_post_padding(t_ftprintf *env, char *s,
								int num_size, int base_size)
{
	int		i;
	char	*new;

	if (!(new = ft_strnew(num_size)))
		return (NULL);
	i = 0;
	while (i < num_size - base_size)
	{
		new[i] = '0';
		i++;
	}
	while (i < num_size)
	{
		new[i] = s[i - (num_size - base_size)];
		if (i == num_size - base_size
				&& env->is_num && env->is_neg)
			new[i] = '0';
		i++;
	}
	new[i] = 0;
	return (new);
}
