/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_keyadd.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 18:58:34 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/13 19:56:52 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

static void		move_line(t_term *term)
{
	if (term->col == term->max_col - 1)
	{
		term->col = 0;
		if (term->row + 1 < term->max_row)
			term->row += 1;
		else
			term->last_prompt_row -= 1;
	}
	else
		term->col += 1;
	move(term->row, term->col);
}

int				ft_keyadd(int key, t_term *term)
{
	char	*tmp;

	if ((key < 32 || key > 126)
			|| ft_strlen(term->buffer) == FT_TERM_BUFFSIZE - 1)
		return (FT_TERM_ERROR);
	if (!term->buffer[term->pos])
	{
		term->buffer[term->pos] = key;
		ft_termprint(key, term);
		move_line(term);
	}
	else
	{
		tmp = term->buffer + term->pos;
		ft_memmove(tmp + 1, tmp, ft_strlen(tmp));
		term->buffer[term->pos] = key;
		ft_termrewrite(term->buffer, term);
		move_line(term);
	}
	++term->pos;
	return (FT_TERM_OK);
}
