/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmap_c.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/08 14:47:57 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/08 15:46:43 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>

char	*ft_strmap_c(char const *s, char (*f)(char))
{
	char	*str;
	int		i;

	str = (char *)malloc(ft_strlen(s) + 1);
	if (!str)
		return (NULL);
	i = 0;
	while (*s)
	{
		str[i] = (*f)(*s);
		i++;
		s++;
	}
	str[i] = '\0';
	return (str);
}
