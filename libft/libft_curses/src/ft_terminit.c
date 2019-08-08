/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_terminit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 17:33:47 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/08 11:31:15 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"
#include <unistd.h>
#include <fcntl.h>

static int	set_error(int code, t_term *term)
{
	if (code == 1)
		term->error = ft_strdup(FT_TERM_ERROR_INIT);
	else if (code == 2)
		term->error = ft_strdup(FT_TERM_ERROR_RAW);
	else if (code == 3)
		term->error = ft_strdup(FT_TERM_ERROR_KEYPAD);
	else if (code == 4)
		term->error = ft_strdup(FT_TERM_ERROR_ECHO);
	return (code);
}

int			ft_terminit(t_term *term)
{
	if (!(term->win = initscr()))
		return (set_error(1, term));
	if (raw() == ERR)
		return (set_error(2, term));
	if (keypad(stdscr, TRUE) == ERR)
		return (set_error(3, term));
	if (noecho() == ERR)
		return (set_error(4, term));
	if (has_colors())
	{
		start_color();
		init_pair(FT_TERM_RED, COLOR_RED, COLOR_BLACK);
		init_pair(FT_TERM_GREEN, COLOR_GREEN, COLOR_BLACK);
		init_pair(FT_TERM_YELLOW, COLOR_YELLOW, COLOR_BLACK);
		init_pair(FT_TERM_BLUE, COLOR_BLUE, COLOR_BLACK);
		init_pair(FT_TERM_CYAN, COLOR_CYAN, COLOR_BLACK);
		init_pair(FT_TERM_MAGENTA, COLOR_MAGENTA, COLOR_BLACK);
		init_pair(FT_TERM_WHITE, COLOR_WHITE, COLOR_BLACK);
	}
	term->prompt_color = none;
	term->str_color = none;
	scrollok(term->win, TRUE);
	return (0);
}
