NAME = ipk-sniffer
EXEC = $(NAME)
source = $(NAME).c

CXX = gcc
RM = rm -f

CFLAGS = -std=gnu99 -Wall
LDFLAGS = -lpcap

OBJFILES = $(source:.c=.o)

.PHONY : all

all : $(EXEC) 

%.o : %.c 
	$(CXX) $(CFLAGS) -c $< -o $@

$(EXEC) : $(OBJFILES)
	$(CXX) $(CFLAGS) -o $@ $(OBJFILES) $(LDFLAGS)

clean:
	$(RM) *.o $(NAME)
