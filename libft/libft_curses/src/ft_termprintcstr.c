/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termprintcstr.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/08 10:14:41 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/08 10:45:47 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

int		ft_termprintcstr(char *s, t_color color, t_term *term)
{
	int		pair;

	pair = ft_termputcolor(color);
	ft_termprintstr(s, term);
	if (pair >= 0)
		attroff(COLOR_PAIR(pair));
	return (0);
}
