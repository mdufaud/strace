/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_get_x_char.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/01/05 17:21:29 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 14:27:10 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

char	*ft_get_x_char(int c, int nb)
{
	int		i;
	char	*new;

	i = 0;
	if (nb <= 0 || !(new = ft_strnew(nb)))
		return (NULL);
	while (i < nb)
	{
		new[i] = c;
		i++;
	}
	new[i] = 0;
	return (new);
}
