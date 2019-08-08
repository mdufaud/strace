# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2013/11/19 14:45:20 by mdufaud           #+#    #+#              #
#    Updated: 2017/11/26 19:29:30 by mdufaud          ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

OS := $(shell uname)
ifeq ($(OS),Linux)
SHELL := /bin/bash
else
SHELL := /bin/sh
endif

ifeq ($(OS),Linux)
ECHO = echo -e
else
ECHO = echo
endif

NAME = libft_printf.a

RED_COLOR = \033[31m
LIGHT_RED_COLOR = \033[1;31m
YELLOW_COLOR = \033[1;33m
BROWN_COLOR = \033[33m
GREEN_COLOR = \033[32m
LIGHT_GREEN_COLOR = \033[32;01m
CYAN_COLOR = \033[36m
LIGHT_CYAN_COLOR = \033[1;36m
PURPLE_COLOR = \033[35m
LIGHT_PURPLE_COLOR = \033[1;35m
BLUE_COLOR = \033[34m
LIGHT_BLUE_COLOR = \033[1;34m
LIGHT_GRAY_COLOR = \033[37m
DARK_GRAY_COLOR = \033[1;30m
BLACK_COLOR = \033[30m
WHITE_COLOR = \033[1;37m
END_COLOR = \033[00m

CFLAGS = cc -Wall -Wextra -Werror
IFLAGS = -I includes -I ../includes
PATH_SRC = src
PATH_OBJ = obj
FIRST_SRC = 1
SRC = ft_clearpos.c\
	  ft_printf.c\
	  ft_fprintf.c\
	  ft_sprintf.c\
	  ft_isflag.c\
	  ft_postdot.c\
	  ft_predot.c\
	  ft_padding.c\
	  ft_pos_padding.c\
	  ft_pre_padding.c\
	  ft_post_padding.c\
	  ft_getflag.c\
	  ft_padnumber.c\
	  ft_prepadnumber.c\
	  ft_get_x_char.c\
	  ft_getarg.c\
	  ft_getuarg.c\
	  ft_printf_arg.c\
	  ftprintf_int.c\
	  ftprintf_uint.c\
	  ftprintf_char.c\
	  ftprintf_str.c\
	  ftprintf_hex.c\
	  ftprintf_bin.c\
	  ftprintf_oct.c\
	  ftprintf_long.c\
	  ftprintf_upperhex.c\
	  ftprintf_addr.c\
	  ft_parse_printf.c\
	  ft_printf_allocate.c\
	  ft_printuntil.c

OBJ = $(patsubst %.c, $(PATH_OBJ)/%.o, $(SRC))
INCLUDES = includes/libftprintf.h\
		   ../includes/libft.h
LIBFT_PATH = ../libft.a

all: $(NAME)

$(PATH_OBJ)/%.o : $(addprefix $(PATH_SRC)/, %.c) $(INCLUDES)
	@mkdir -p $(PATH_OBJ)
	@$(CFLAGS) $(IFLAGS) -o $@ -c $<
	@if [ $(FIRST_SRC) == 1 ]; then \
		$(eval FIRST_SRC = 0) \
		$(ECHO) "$(LIGHT_GREEN_COLOR)$(NAME) objects : [ $(END_COLOR)\c"; \
	fi
	@$(ECHO) "$(LIGHT_GREEN_COLOR).$(END_COLOR)\c"

$(NAME): $(OBJ)
	@$(ECHO) "$(LIGHT_GREEN_COLOR) ]$(END_COLOR)"
	@ar rcs $@ $^
	@$(ECHO) "$(GREEN_COLOR)"
	@$(ECHO) ""
	@$(ECHO) "    ____       _       _    __   ____                    "
	@$(ECHO) "   |  _ \ _ __(_)_ __ | |_ / _| |  _ \  ___  _ __   ___  "
	@$(ECHO) "   | |_) |  __| |  _ \| __| |_  | | | |/ _ \|  _ \ / _ \\ "
	@$(ECHO) "   |  __/| |  | | | | | |_|  _| | |_| | (_) | | | |  __/ "
	@$(ECHO) "   |_|   |_|  |_|_| |_|\__|_|   |____/ \___/|_| |_|\___| "
	@$(ECHO) ""
	@$(ECHO) "$(END_COLOR)"

clean:
	@rm -f $(OBJ)
	@$(ECHO) "$(CYAN_COLOR)[ $(NAME) objects deleted ]$(END_COLOR)"

fclean: clean
	@rm -rf $(NAME)
	@$(ECHO) "$(RED_COLOR)[ $(NAME) deleted ]$(END_COLOR)"

re: fclean all

.PHONY: all clean fclean re
