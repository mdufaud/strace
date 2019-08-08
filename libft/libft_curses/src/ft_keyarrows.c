/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_keyarrows.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 20:28:54 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/09 12:10:25 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

int		ft_keyarrowright(t_term *term)
{
	if (term->pos < (int)ft_strlen(term->buffer))
	{
		if (term->max_col - 1 == term->col)
		{
			term->row++;
			term->col = 0;
		}
		else
			term->col++;
		move(term->row, term->col);
		term->pos++;
	}
	return (FT_TERM_OK);
}

int		ft_keyarrowleft(t_term *term)
{
	if (term->pos > 0)
	{
		if (!term->col && term->row)
		{
			term->col = term->max_col - 1;
			term->row--;
		}
		else
			term->col--;
		term->pos--;
		move(term->row, term->col);
	}
	return (FT_TERM_OK);
}

int		ft_keyarrowdown(t_term *term)
{
	int		cmp;

	if (!term->hist)
		return (FT_TERM_ERROR);
	cmp = ft_strcmp(term->buffer, term->hist->content);
	if (term->hist)
	{
		ft_bzero(term->buffer, FT_TERM_BUFFSIZE);
		term->pos = 0;
		if (!cmp && term->hist->prev)
		{
			term->hist = term->hist->prev;
			term->pos = term->hist->content_size - 1;
			ft_memcpy(term->buffer, term->hist->content, term->pos);
		}
		ft_termresetline(term->buffer, term);
	}
	return (FT_TERM_OK);
}

int		ft_keyarrowup(t_term *term)
{
	if (!term->hist)
		return (FT_TERM_ERROR);
	if (!ft_strcmp(term->buffer, term->hist->content) && term->hist->next)
		term->hist = term->hist->next;
	if (term->hist)
	{
		ft_bzero(term->buffer, FT_TERM_BUFFSIZE);
		term->pos = term->hist->content_size - 1;
		ft_memcpy(term->buffer, term->hist->content, term->pos);
		ft_termresetline(term->buffer, term);
	}
	return (FT_TERM_OK);
}
