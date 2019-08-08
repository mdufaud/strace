/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termaddcol.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/13 19:39:55 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/13 19:48:34 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

void	ft_termaddcol(t_term *term, int size)
{
	if (term->col + size > term->max_col - 1)
	{
		term->row += (term->col + size) / term->max_col;
		if (term->row >= term->max_row)
		{
			term->row = term->max_row - 1;
			term->last_prompt_row = term->row
				- ((ft_strlen(term->buffer) + term->prompt_len)
				/ term->max_col);
		}
		term->col = (term->col + size) % term->max_col;
	}
	else
		term->col += size;
}
