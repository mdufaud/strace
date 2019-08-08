/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_padnumber.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/04/30 22:47:41 by mdufaud           #+#    #+#             */
/*   Updated: 2016/01/05 19:33:35 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

static void	fillstr_with_char(char *s, int *from, int to, char c)
{
	while (*from < to)
	{
		s[*from] = c;
		*from += 1;
	}
}

static void	fillstr_with_str(char *s, int *from, int to, char *str)
{
	int		i;

	i = 0;
	while (*from < to)
	{
		s[*from] = str[i];
		*from += 1;
		i++;
	}
}

char		*ft_padnumber(t_ftprintf *e, char *number)
{
	char	*new_number;
	int		zero_len;
	int		len;
	int		i;

	zero_len = ft_postdot(e);
	len = ft_strlen(number);
	if (zero_len - len <= 0)
		return (ft_strdup(number));
	if (!(new_number = (char *)malloc(zero_len + 1)))
		return (NULL);
	i = 0;
	fillstr_with_char(new_number, &i, zero_len - len, '0');
	fillstr_with_str(new_number, &i, zero_len, number);
	new_number[i] = 0;
	return (new_number);
}
