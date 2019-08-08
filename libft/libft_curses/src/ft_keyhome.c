/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_keyhome.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 20:47:34 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/09 12:07:52 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

int		ft_keyhome(t_term *term)
{
	term->col = term->prompt_len;
	term->row = term->last_prompt_row;
	move(term->row, term->col);
	refresh();
	term->pos = 0;
	return (1);
}
