/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termprompt.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 19:21:57 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/08 15:56:24 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"
#include <unistd.h>

void	ft_termprompt(t_term *term)
{
	if (term->prompt)
	{
		ft_termprintcstr(term->prompt, term->prompt_color, term);
		term->last_prompt_row = term->row;
		refresh();
	}
}
