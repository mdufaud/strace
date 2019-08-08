/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_pos_padding.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/21 16:19:40 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/21 16:28:19 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libftprintf.h"

static void	replace_neg(char *s)
{
	int		i;

	i = 0;
	while (s[i] && s[i] != '-')
		i++;
	if (s[i] && s[i] == '-')
		s[i] = '0';
	i = 0;
	while (s[i] && s[i] == ' ')
		i++;
	if (s[i] && s[i] == '0')
		s[i] = '-';
}

static int	flag_padding(t_ftprintf *env, char **s, int total_len, int num_len)
{
	char	*tmp;

	if (env->is_num && !env->is_neg && env->is_plus && !env->is_unsigned)
	{
		tmp = ft_strjoin("+", *s);
		free(*s);
		*s = tmp;
	}
	else if (env->is_num && !env->is_neg && env->is_space
			&& !env->is_unsigned && total_len < num_len)
	{
		tmp = ft_strjoin(" ", *s);
		free(*s);
		*s = tmp;
		return (1);
	}
	return (0);
}

static void	is_num(t_ftprintf *env, char **s, int base_size, int num_len)
{
	char	*tmp;

	if ((num_len = ft_postdot(env)))
		num_len += env->is_neg;
	num_len = num_len > base_size ? num_len : base_size;
	tmp = ft_post_padding(env, *s, num_len, base_size);
	free(*s);
	*s = tmp;
	if (!env->is_neg && !env->is_unsigned)
		num_len += env->is_plus;
}

int			ft_pos_padding(t_ftprintf *env, char **s, int total_len)
{
	int		num_len;
	char	*tmp;
	int		base_size;
	int		new_total_len;

	base_size = ft_strlen(*s);
	num_len = base_size;
	if (env->is_num)
		is_num(env, s, base_size, num_len);
	new_total_len = total_len;
	new_total_len = new_total_len > num_len ? new_total_len : num_len;
	tmp = ft_pre_padding(env, *s, new_total_len, num_len);
	free(*s);
	*s = tmp;
	if (env->is_num && env->is_neg)
		replace_neg(*s);
	new_total_len += flag_padding(env, s, total_len, num_len);
	return (new_total_len);
}
