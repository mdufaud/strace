/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termprintcendl.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/08 10:45:09 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/08 10:47:51 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

int		ft_termprintcendl(char *s, t_color color, t_term *term)
{
	int		pair;

	pair = ft_termputcolor(color);
	ft_termprintendl(s, term);
	if (pair >= 0)
		attroff(COLOR_PAIR(pair));
	return (0);
}
