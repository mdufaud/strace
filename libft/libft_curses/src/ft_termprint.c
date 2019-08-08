/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termprint.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/25 22:07:50 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/14 18:40:59 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

int		ft_termprint(int key, t_term *term)
{
	int		pair;

	pair = ft_termputcolor(term->str_color);
	attron(COLOR_PAIR(pair));
	addch(key);
	if (pair >= 0)
		attroff(COLOR_PAIR(pair));
	move(term->row, term->col);
	refresh();
	return (0);
}
