/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libftprintf.h                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2013/12/17 15:52:22 by mdufaud           #+#    #+#             */
/*   Updated: 2017/11/22 15:38:38 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFTPRINTF_H
# define LIBFTPRINTF_H

# include <stdarg.h>
# include <strings.h>
# include <stdlib.h>
# include "libft.h"

# define HH_VALUE (2 << 0)
# define H_VALUE (2 << 1)
# define LL_VALUE (2 << 2)
# define L_VALUE (2 << 3)
# define J_VALUE (2 << 4)
# define Z_VALUE (2 << 5)

# if defined(__linux__)
#  include <stdint.h>
#  define UNIX_STR_CONDITION env->is_num
# endif
# if defined(__APPLE__)
#  define UNIX_STR_CONDITION 1
# endif

typedef struct		s_ftprintf
{
	char			*buffer;
	char			*s;
	char			*pos;
	int				i;
	int				w;
	int				count;
	int				active_color;
	int				is_hash;
	int				is_0;
	int				is_plus;
	int				is_less;
	int				is_space;
	int				ret;
	int				is_num;
	int				is_neg;
	int				is_unsigned;
	int				size_flag;
	va_list			arg;
}					t_ftprintf;

typedef struct		s_printf_match
{
	char			*arg;
	char			*(*f)(t_ftprintf *);
}					t_printf_match;

# ifndef LIBFT_COLOR
#  define LIBFT_COLOR

typedef enum		e_color
{
	red,
	bourg,
	white,
	blue,
	dark,
	purple,
	cyan,
	yellow,
	green,
	pink,
	end_color
}					t_color;
# endif

int					ft_printf(char *format, ...);
int					ft_fprintf(int fd, char *format, ...);
int					ft_sprintf(char **s, char *format, ...);
t_ftprintf			*ft_printf_allocate(char *s);
void				ft_parse_printf(t_ftprintf *env);
int					printf_arg(t_ftprintf *env);
int					ft_postdot(t_ftprintf *env);
int					ft_predot(t_ftprintf *env);
int					ft_isflag(int c);
void				ft_getflag(t_ftprintf *env, char *s);
char				*ft_padnumber(t_ftprintf *e, char *number);
char				*ft_prepadnumber(t_ftprintf *e, char *before, char *number);
int					ft_padding(t_ftprintf *env, char **s);
int					ft_pos_padding(t_ftprintf *env, char **s, int total_len);
char				*ft_pre_padding(t_ftprintf *env, char *s,
										int total_size, int num_size);
char				*ft_post_padding(t_ftprintf *env, char *s,
										int num_size, int base_size);
char				*ft_get_x_char(int c, int nb);
void				ft_clearpos(t_ftprintf *env);
void				ft_printuntil(t_ftprintf *env);
long long			ft_getarg(t_ftprintf *env);
unsigned long long	ft_getuarg(t_ftprintf *env);
char				*ftprintf_int(t_ftprintf *env);
char				*ftprintf_long(t_ftprintf *env);
char				*ftprintf_uint(t_ftprintf *env);
char				*ftprintf_char(t_ftprintf *env);
char				*ftprintf_str(t_ftprintf *env);
char				*ftprintf_hex(t_ftprintf *env);
char				*ftprintf_bin(t_ftprintf *env);
char				*ftprintf_oct(t_ftprintf *env);
char				*ftprintf_upperhex(t_ftprintf *env);
char				*ftprintf_addr(t_ftprintf *env);
#endif
