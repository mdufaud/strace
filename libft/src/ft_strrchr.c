/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrchr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/20 16:01:50 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/10 11:41:09 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>

char	*ft_strrchr(const char *s, int c)
{
	int		i;
	char	f;

	i = 0;
	f = (char)c;
	while (s[i])
		i++;
	i++;
	while (i != 0)
	{
		if (s[i] == f)
			return ((char *)(s + i));
		i--;
	}
	return (NULL);
}
