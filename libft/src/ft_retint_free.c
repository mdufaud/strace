/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_retint_free.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/06/08 12:47:53 by mdufaud           #+#    #+#             */
/*   Updated: 2014/06/08 12:47:59 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <stdlib.h>
#include <unistd.h>

int		ft_retint_free(int fd, char **s, char ***tab, void **data)
{
	if (fd > 2)
		close(fd);
	if (s)
		ft_strdel(s);
	if (tab)
		ft_tabfree(tab);
	if (data)
	{
		free(*data);
		*data = NULL;
	}
	return (0);
}
