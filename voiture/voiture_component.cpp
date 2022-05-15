#include <pybind11/pybind11.h>

char version[]="1.0";

char const* getVersion() {
	return version;
}

class Voiture
{
    public:
        Voiture(const std::string &nom, int litreEssence) : nom(nom), litreEssence(litreEssence) {}
        ~Voiture() {}

        void rouler() { litreEssence--; }
        const std::string &get_nom() const { return nom; }
        int get_litreEssence() const { return litreEssence; }
		void setEssence(int &essence_) { litreEssence = essence_; }

    private:
        std::string nom;
        int litreEssence;
};
 
namespace py = pybind11;


PYBIND11_MODULE(voiture_component,greetings)
{
  greetings.doc() = "greeting_object 1.0";
  greetings.def("getVersion", &getVersion, "a function returning the version");
  
   // bindings to Voiture class
    py::class_<Voiture>(greetings, "Voiture", py::dynamic_attr())
        .def(py::init<const std::string &, int>())
        .def("rouler", &Voiture::rouler)
        .def("get_litreEssence", &Voiture::get_litreEssence)
        .def("get_nom", &Voiture::get_nom)
		.def("setEssence", &Voiture::setEssence);
}