/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termclearline.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/08 18:08:58 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/09 12:11:24 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

void	ft_termclearline(t_term *term)
{
	ft_termvalidatetab(term);
	term->reload_pos = term->pos;
	term->reload_row = term->row;
	term->reload_col = term->col;
	term->col = 0;
	term->row = term->last_prompt_row;
	move(term->row, term->col);
	term->pos = 0;
	clrtobot();
	refresh();
}
