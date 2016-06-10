// Generate pseudorandom numbers using MT19937 PRNG
//
// to compile and run:
// $ g++ pseudorandom.cpp --std=c++11 -o pseudorandom
// $ ./pseudorandom <SEED> <N>

#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

std::string USAGE =
  "Usage: pseudorandom <SEED> <N>\n\n"
  "  Generate pseudorandom numbers using MT19937 PRNG\n\n"
  "Options:\n"
  "  SEED: seed of the PRNG\n"
  "  N: number of elements to generate\n";

void print_help()
{
  std::cout << USAGE;
}

int main(int argc, char* argv[])
{
  if (argc != 3) {
    print_help();
    return 0;
  }

  int seed = 0;
  int nb_elements = 0;
  std::vector<std::string> args(argv, argv + argc);
  std::mt19937 rand;

  try {
    seed = stoi(args[1]);
    nb_elements = stoi(args[2]);
  } catch (std::invalid_argument) {
    std::cout << "* Invalid Arguments /!\\\n\n";
    print_help();
    return 0;
  }

  rand.seed(seed);
  std::cout << "[";
  for (int i = 0; i < nb_elements; i++) {
    std::cout << ((i == 0) ? "" : ", ") << rand();
  }
  std::cout << "]\n";
}
