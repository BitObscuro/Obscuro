App_Cpp_Files :=  $(wildcard *.cpp)
App_Include_Paths := -I.
App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)
App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags :=  -lpthread -lm -lssl -lcrypto -lsecp256k1 -Wl,-rpath -Wl,/usr/local/lib
App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)
App_Name := user

all: $(App_Name)

run: all
%.o: %.cpp
	$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

.PHONY: clean

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/MyEnclave_u.* $(Enclave_Cpp_Objects) MyEnclave/MyEnclave_t.*
