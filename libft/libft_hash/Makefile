# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2013/11/19 14:45:20 by mdufaud           #+#    #+#              #
#    Updated: 2017/11/28 21:06:04 by mdufaud          ###   ########.fr        #
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

NAME = libft_hash.a

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

PIZZA = 🍕

CFLAGS = cc -Wall -Wextra -Werror
IFLAGS = -I includes -I ../includes
PATH_SRC = src
PATH_OBJ = obj
FIRST_SRC = 1
SRC = ft_hashfind.c\
	  ft_hashdebug.c\
	  ft_hashnew.c\
	  ft_hashadd.c\
	  ft_hashprint_all.c\
	  ft_hashprint.c\
	  ft_hashprintendl.c\
	  ft_hashfree.c\
	  ft_hashdel.c\
	  ft_print_t_type.c


OBJ = $(patsubst %.c, $(PATH_OBJ)/%.o, $(SRC))
INCLUDES = includes/libft_hash.h\
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
	@$(ECHO) "$(PIZZA)  Libft hash done $(PIZZA)"
	@$(ECHO) "$(END_COLOR)"

clean:
	@rm -f $(OBJ)
	@$(ECHO) "$(CYAN_COLOR)[ $(NAME) objects deleted ]$(END_COLOR)"

fclean: clean
	@rm -rf $(NAME)
	@rm -df $(PATH_OBJ)
	@$(ECHO) "$(RED_COLOR)[ $(NAME) deleted ]$(END_COLOR)"

re: fclean all

.PHONY: all clean fclean re
