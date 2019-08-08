/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termprintendl.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/08 10:30:17 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/13 20:19:39 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

int		ft_termprintendl(char *s, t_term *term)
{
	int		size;

	printw("%s", s);
	size = ft_strtablen(s, 8);
	ft_termaddcol(term, size);
	if (term->row + 1 >= term->max_row)
		addch('\n');
	else
		term->row += 1;
	term->col = 0;
	move(term->row, term->col);
	refresh();
	return (0);
}
