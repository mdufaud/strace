/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termreloadline.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/08 18:13:15 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/09 12:11:54 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

void	ft_termreloadline(t_term *term)
{
	ft_termprompt(term);
	ft_termprintcstr(term->buffer, term->str_color, term);
	term->pos = term->reload_pos;
	term->col = term->reload_col;
	move(term->row, term->col);
	refresh();
}
