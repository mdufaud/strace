/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtablen.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/13 20:04:24 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/13 20:07:56 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

int		ft_strtablen(char *s, int tab_stop)
{
	int		i;
	int		size;

	i = 0;
	size = 0;
	while (s[i])
	{
		if (s[i] == '\t')
			size = size + (tab_stop - (size % tab_stop));
		else
			size++;
		i++;
	}
	return (size);
}
