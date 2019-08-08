/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/11/20 14:02:10 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/16 14:30:13 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"
#include <string.h>

size_t	ft_strlcat(char *dst, const char *src, size_t size)
{
	size_t	i;
	size_t	s_len;
	size_t	d_len;

	d_len = ft_strlen(dst);
	s_len = ft_strlen(src);
	if (d_len >= size)
		return (size + s_len);
	i = d_len + s_len;
	if (i >= size)
		ft_strncat(dst, src, (size - d_len - 1));
	else
		ft_strcat(dst, src);
	return (i);
}
