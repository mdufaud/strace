/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/20 14:47:13 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/10 11:38:16 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>

char	*ft_strchr(const char *s, int c)
{
	char	f;
	int		i;

	f = (char)c;
	i = 0;
	while (s[i])
	{
		if (s[i] == f)
			return ((char *)(s + i));
		i++;
	}
	if (s[i] == f)
		return ((char *)(s + i));
	else
		return (NULL);
}
