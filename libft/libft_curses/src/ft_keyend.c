/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_keyend.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 20:47:42 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/09 12:08:02 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

int		ft_keyend(t_term *term)
{
	int		bl;

	bl = ft_strlen(term->buffer);
	term->col = (bl + term->prompt_len) % term->max_col;
	term->row = term->last_prompt_row;
	term->row += ((bl + term->prompt_len) / term->max_col);
	if (term->row >= term->max_row)
		term->row = term->max_row - 1;
	move(term->row, term->col);
	refresh();
	term->pos = bl;
	return (1);
}
