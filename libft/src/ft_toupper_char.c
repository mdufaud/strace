/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_toupper_char.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/08 14:57:00 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/08 14:57:18 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

char	ft_toupper_char(char c)
{
	if (c >= 'a' && c <= 'z')
		return (c - 32);
	else
		return (c);
}
