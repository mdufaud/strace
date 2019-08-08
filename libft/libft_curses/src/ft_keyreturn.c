/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_keyreturn.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 18:53:50 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/08 17:50:54 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

int			ft_keyreturn(t_term *term)
{
	t_dlist		*new;
	int			len;

	if (!(term->opt & FT_TERM_NOHISTORY) && (len = ft_strlen(term->buffer)))
	{
		ft_dlstfirst(&term->hist);
		new = ft_dlstnew(term->buffer, len + 1);
		ft_dlstadd(&term->hist, new);
	}
	ft_keyend(term);
	term->col = 0;
	if (term->row + 1 >= term->max_row)
		addch('\n');
	else
		term->row += 1;
	move(term->row, term->col);
	term->buffer[term->pos] = '\n';
	term->code -= FT_TERM_READ;
	return (1);
}
