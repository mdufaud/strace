/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strreplace.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/13 20:23:20 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/13 20:47:12 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		count_str(char *s, char *replace)
{
	int		rp;
	int		i;
	int		count;

	i = 0;
	count = 0;
	while (s[i])
	{
		rp = 0;
		while (s[i + rp] == replace[rp] && replace[rp])
			rp++;
		if (!replace[rp])
			count++;
		i++;
	}
	return (count);
}

void	copy_from_to(char *s, char *from, char *to, char *new)
{
	int		i;
	int		j;
	int		k;
	int		to_len;

	i = 0;
	j = 0;
	to_len = ft_strlen(to);
	while (s[i])
	{
		k = 0;
		while (s[i + k] == from[k] && from[k])
			k++;
		if (!from[k])
		{
			ft_strcpy(new + j, to);
			i = i + k;
			j = j + to_len;
		}
		else
			new[j++] = s[i++];
	}
	new[j] = 0;
}

char	*ft_strreplace(char *s, char *from, char *to)
{
	int		i;
	char	*new;

	i = count_str(s, from);
	i = ft_strlen(s) - (i * ft_strlen(from)) + (i * ft_strlen(to));
	if (!(new = ft_strnew(i)))
		return (NULL);
	copy_from_to(s, from, to, new);
	new[i] = 0;
	return (new);
}
