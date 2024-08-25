# Define the compiler
CXX = g++

# Define the flags
CXXFLAGS = -std=c++11 -Wall -O2
LDFLAGS =  -lbcc -lpthread

# Define the target executable
TARGET = log_server 

# Define the source files
SRCS = log_server.cpp

# Define the object files
OBJS = $(SRCS:.cpp=.o)

# The rule to build the target
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# The rule to build the object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up the build
.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJS)