/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strstr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/21 15:54:14 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/10 11:43:51 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "./libft.h"

char	*ft_strstr(const char *s1, const char *s2)
{
	unsigned int	len;
	int				i;

	i = 0;
	if (*s2 == '\0')
		return ((char *)s1);
	len = ft_strlen(s2);
	while (s1[i])
	{
		if (ft_strncmp(s2, s1 + i, len) == 0)
			return ((char *)(s1 + i));
		i++;
	}
	return (NULL);
}
