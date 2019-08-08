/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termputcolor.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/08 10:42:50 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/15 14:33:19 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

static const t_term_compat_libft_color	g_tabcolor[] = {
	{none, FT_TERM_WHITE},
	{red, FT_TERM_RED},
	{green, FT_TERM_GREEN},
	{yellow, FT_TERM_YELLOW},
	{blue, FT_TERM_BLUE},
	{cyan, FT_TERM_CYAN},
	{pink, FT_TERM_MAGENTA},
	{white, FT_TERM_WHITE},
	{end_color, -1}
};

int		ft_termputcolor(t_color color)
{
	int		i;
	int		pair;

	i = 0;
	pair = -1;
	while (g_tabcolor[i].term_color != -1)
	{
		if (g_tabcolor[i].libft_color == color)
		{
			pair = g_tabcolor[i].term_color;
			attron(COLOR_PAIR(pair));
			break ;
		}
		i++;
	}
	return (pair);
}
