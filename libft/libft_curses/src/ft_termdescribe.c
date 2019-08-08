/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termdescribe.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/10/25 15:59:24 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/08 16:03:39 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

void	ft_termdescribe(t_term *term)
{
	mvprintw(0, 0, "Term:");
	mvprintw(1, 4, "max_row: %d, max_col: %d",
			term->max_row, term->max_col);
	mvprintw(2, 4, "row: %d, col: %d", term->row, term->col);
	mvprintw(3, 4, "pos:%d, last_prompt_row: %d",
			term->pos, term->last_prompt_row);
	mvprintw(4, 4, "buffer %p with %zu content: '%s'",
			term->buffer, ft_strlen(term->buffer), term->buffer);
	term->row = 5;
	term->col = 0;
	move(term->row, term->col);
}
