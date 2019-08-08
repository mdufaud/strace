/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft_arg.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/02/23 16:18:30 by mdufaud           #+#    #+#             */
/*   Updated: 2016/10/25 17:56:19 by mdufaud          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_ARG_H
# define LIBFT_ARG_H

# include "libft.h"

/*
** Arg macro
*/

# define ARG_INVALID_OPTION (2 << 0)

# define ARGFIND_ALL (2 << 1)
# define ARGFIND_STOP_FALSE (2 << 3)
# define ARGFIND_STOP_FIRST (2 << 2)
# define ARGFIND_RET_INDEX (2 << 0)

/*
** Arg struct
*/

typedef struct		s_arg
{
	int				argc;
	int				sum;
	char			**argv;
	char			**arglist;
	int				error_sum;
	char			*error;
	char			*(*fetch)(struct s_arg *, char *);
	int				(*check)(struct s_arg *, char *);
	void			(*get_error)(struct s_arg *);
	void			(*arg_add)(struct s_arg *, char *);
	char			**(*none)(struct s_arg *);
}					t_arg;

/*
** Arg Functions
*/

int					ft_argcheck_fun(t_arg *arg, char *s);
char				*ft_argfetch_fun(t_arg *arg, char *s);
int					ft_argcheck(char *arg, char **arglist, int sum);
char				*ft_argfetch(int argc, char **argv, char *arg);
int					ft_argsum(int argc, char **argv, char **arglist);
int					ft_argfind(char *argv, char *arglist, int mask);
t_arg				*ft_argnew(int argc, char **argv, char *argliststr);
void				ft_argfree(t_arg **arg);
int					ft_isarg(char *arg);
void				ft_argerror(t_arg *arg);
void				ft_argadd(t_arg *arg, char *s);
char				**ft_argnone(t_arg *arg);
int					ft_argsearch(char *argv, char **alst);

#endif
