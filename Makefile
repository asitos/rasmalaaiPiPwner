CXX = g++
CXXFLAGS = -Wall -Wextra -Werror -std=c++17 -O2
INCLUDES = -I./include

TARGET = authsim
SRC = src/main.cpp
OBJ = $(SRC:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJ)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f src/*.o $(TARGET)
