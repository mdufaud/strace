/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_termread.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 19:32:25 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/08 15:56:37 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft_curses.h"
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

int			ft_termread(int *key, t_term *term)
{
	*key = getch();
	(void)term;
	return (1);
}
