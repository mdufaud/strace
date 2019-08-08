/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strcmp_map.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/08 14:51:01 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/08 15:26:49 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

int		ft_strcmp_map(const char *str1, const char *str2, char (*f)(char))
{
	int				i;
	unsigned char	*s1;
	unsigned char	*s2;
	unsigned char	mapped;

	i = 0;
	s1 = (unsigned char *)str1;
	s2 = (unsigned char *)str2;
	while (s1[i])
	{
		mapped = f(s2[i]);
		if (s1[i] == mapped)
			i++;
		else
			return (s1[i] - mapped);
	}
	return (s1[i] - s2[i]);
}
