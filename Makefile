CXX=g++
CXXFLAGS=-std=c++17 -Wall
TARGET=capture_engine

all: $(TARGET)

$(TARGET): capture_engine.cpp
	$(CXX) $(CXXFLAGS) -o $(TARGET) capture_engine.cpp -lpcap

clean:
	rm -f $(TARGET)
