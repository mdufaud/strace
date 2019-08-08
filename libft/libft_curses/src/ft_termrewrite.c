/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termrewrite.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 20:27:37 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/13 19:51:18 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

void	ft_termrewrite(char *s, t_term *term)
{
	int		old_row;
	int		old_col;
	int		old_pos;
	int		true_pos;

	old_row = term->row;
	old_col = term->col;
	old_pos = term->pos;
	ft_termresetline(s, term);
	true_pos = (ft_strlen(term->buffer) + term->prompt_len) % term->max_col;
	if (old_row + 1 >= term->max_row && true_pos == 0)
		old_row--;
	term->row = old_row;
	term->col = old_col;
	term->pos = old_pos;
	move(term->row, term->col);
	refresh();
}
