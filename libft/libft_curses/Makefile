# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: mdufaud <mdufaud@student.42.fr>            +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2013/11/19 14:45:20 by mdufaud           #+#    #+#              #
#    Updated: 2017/11/28 21:07:02 by mdufaud          ###   ########.fr        #
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

NAME = libft_curses.a

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

AVOCADO = 🥑

LIB_HASH_INCLUDE_PATH = ../libft_hash/includes
CFLAGS = cc -Wall -Wextra -Werror
IFLAGS = -I includes -I ../includes -I $(LIB_HASH_INCLUDE_PATH)
PATH_SRC = src
PATH_OBJ = obj
FIRST_SRC = 1
SRC = ft_termnew.c\
	  ft_termdescribe.c\
	  ft_termprompt.c\
	  ft_termsetprompt.c\
	  ft_terminit.c\
	  ft_termexit.c\
	  ft_termsize.c\
	  ft_termread.c\
	  ft_termcanread.c\
	  ft_termaddcmd.c\
	  ft_termaddoptions.c\
	  ft_termsetcolor.c\
	  ft_termaddcol.c\
	  ft_termgnl.c\
	  ft_termdel.c\
	  ft_termgetkey.c\
	  ft_termresetline.c\
	  ft_termhome.c\
	  ft_termputs.c\
	  ft_termrewrite.c\
	  ft_termprint.c\
	  ft_termputcolor.c\
	  ft_termprintstr.c\
	  ft_termprintendl.c\
	  ft_termprintcstr.c\
	  ft_termprintcendl.c\
	  ft_termvalidatetab.c\
	  ft_termclearline.c\
	  ft_termreloadline.c\
	  ft_keytab.c\
	  ft_keytab_options.c\
	  ft_keyadd.c\
	  ft_keyhome.c\
	  ft_keyend.c\
	  ft_keyreturn.c\
	  ft_keyexit.c\
	  ft_keyarrows.c\
	  ft_keybackdel.c\
	  ft_keydel.c

OBJ = $(patsubst %.c, $(PATH_OBJ)/%.o, $(SRC))
INCLUDES = includes/libft_curses.h\
		   $(LIB_HASH_INCLUDE_PATH)/libft_hash.h\
		   ../includes/libft.h
LIBFT_PATH = ../libft.a
LIBFT_HASH_PATH = ../libft_hash/libft_hash.a

all: $(NAME)

$(PATH_OBJ)/%.o : $(addprefix $(PATH_SRC)/, %.c) $(INCLUDES)
	@mkdir -p $(PATH_OBJ)
	@$(CFLAGS) $(IFLAGS) -o $@ -c $<
	@if [ $(FIRST_SRC) == 1 ]; then \
		$(eval FIRST_SRC = 0) \
		$(ECHO) "$(LIGHT_GREEN_COLOR)$(NAME) objects : [ $(END_COLOR)\c"; \
	fi
	@$(ECHO) "$(LIGHT_GREEN_COLOR).$(END_COLOR)\c"

$(NAME): $(OBJ) $(LIBFT_PATH) $(LIBFT_HASH_PATH)
	@$(ECHO) "$(LIGHT_GREEN_COLOR) ]$(END_COLOR)"
	@ar rcs $@ $^
	@$(ECHO) "$(GREEN_COLOR)"
	@$(ECHO) "$(AVOCADO)  Lib curses done $(AVOCADO)"
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
