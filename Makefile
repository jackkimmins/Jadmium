CXX = g++
CXXFLAGS = -std=c++20 -Wall -O3
SRC_DIR = src
BUILD_DIR = build
CPP_SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
HPP_HEADERS = $(wildcard $(SRC_DIR)/*.hpp)
OBJECTS = $(CPP_SOURCES:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)
BINARY = $(BUILD_DIR)/webserver
LIBS = -lpthread -lz
$(shell mkdir -p $(BUILD_DIR))

all: $(BINARY)
$(BINARY): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp $(HPP_HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY)

run:
	$(BINARY)

.PHONY: all clean
