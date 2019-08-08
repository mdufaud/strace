/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strunion.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/14 17:17:22 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/14 17:53:30 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	calc_len(char **tab, int unite_len)
{
	int		i;
	int		len;

	i = 0;
	len = 0;
	while (tab[i])
	{
		len += ft_strlen(tab[i]);
		if (tab[i + 1])
			len += unite_len;
		i++;
	}
	return (len);
}

static void	fill_string(char **tab, char *s, char *unite)
{
	int		i;

	i = 0;
	while (tab[i])
	{
		ft_strcat(s, tab[i]);
		if (tab[i + 1])
			ft_strcat(s, unite);
		i++;
	}
}

char		*ft_strunion(char **tab, char *unite)
{
	int		len;
	char	*new;
	int		unite_len;

	unite_len = ft_strlen(unite);
	len = calc_len(tab, unite_len);
	if (!(new = ft_strnew(len)))
		return (NULL);
	fill_string(tab, new, unite);
	new[len] = 0;
	return (new);
}
