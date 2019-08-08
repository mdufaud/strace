/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termsize.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 17:39:56 by mdufaud           #+#    #+#             */
/*   Updated: 2016/11/28 16:38:48 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

void	ft_termsize(t_term *term)
{
	getmaxyx(stdscr, term->max_row, term->max_col);
	getyx(stdscr, term->row, term->col);
}
