#include <pybind11/pybind11.h>

char version[]="1.0";

char const* getVersion() {
	return version;
}

char const* greet() {
  return "hello, world";
}

namespace py = pybind11;


PYBIND11_MODULE(hello_component,greetings)
{
  greetings.doc() = "greeting_object 1.0";
  
  greetings.def("greet", &greet, "a function saying hello");
  greetings.def("getVersion", &getVersion, "a function returning the version");
}
