NAME := sniffex
CC  := g++
SRCS := $(wildcard *.cpp)
OBJS := ${SRCS:.cpp=.o}
INCLUDE_DIRS :=
LIBRARY_DIRS :=
LIBRARIES := pcap boost_program_options-mt log4cxx boost_thread-mt boost_system-mt boost_iostreams-mt boost_date_time pthread

CPPFLAGS += $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
CPPFLAGS += -Wall -g -O
LDFLAGS += $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDLIBS += $(foreach library,$(LIBRARIES),-l$(library))

.PHONY: all clean

$(NAME): $(OBJS) 
	g++ $(LDFLAGS) $(OBJS) -o $(NAME) $(LDLIBS)

all: ${NAME}

clean:
	@- rm -rf $(OBJS) $(NAME)
dep-install:
	apt-get update
	apt-get -y install liblog4cxx10-dev libboost-iostreams-dev libboost-thread-dev libboost-system-dev 