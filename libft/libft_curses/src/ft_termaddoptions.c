/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termaddoptions.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/24 19:02:56 by mdufaud           #+#    #+#             */
/*   Updated: 2016/10/25 17:31:04 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"

void	ft_termaddoptions(t_term *term, t_hash *hash)
{
	ft_hashadd(&term->options, hash);
}
