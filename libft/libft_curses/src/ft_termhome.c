/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termhome.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 20:57:22 by mdufaud           #+#    #+#             */
/*   Updated: 2016/11/27 20:36:52 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

void	ft_termhome(t_term *term)
{
	term->col = term->prompt_len;
	term->row = term->last_prompt_row;
	move(term->row, term->col);
	term->pos = 0;
}
