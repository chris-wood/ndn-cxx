/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2014 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#include "pib.hpp"

#include "util/io.hpp"
#include "util/config-file.hpp"
#include "security/key-chain.hpp"

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/filesystem.hpp>

namespace ndn {
namespace pib {

int
main(int argc, char** argv)
{
  namespace po = boost::program_options;
  namespace fs = boost::filesystem;

  std::string owner;
  std::string dbDir;
  std::string tpmLocator;
  Face face;

  std::cerr << "hello" << std::endl;

  po::options_description description(
    "General Usage\n"
    "  ndn-pib [-h] -o owner -d database_dir -t tpm_locator\n"
    "General options");

  description.add_options()
    ("help,h",     "produce help message")
    ("owner,o",    po::value<std::string>(&owner),
                   "Name of the owner, PIB will listen to /localhost/pib/[owner].")
    ("database,d", po::value<std::string>(&dbDir),
                   "Absolute path to the directory of PIB database, /<database_dir>/pib.db")
    ("tpm,t",      po::value<std::string>(&tpmLocator),
                   "URI of the tpm. e.g., tpm-file:/var")
    ;

  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argc, argv, description), vm);
    po::notify(vm);
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    std::cerr << description << std::endl;
    return 1;
  }

  if (vm.count("help") != 0) {
    std::cerr << description << std::endl;
    return 0;
  }

  try {
    if (vm.count("owner") == 0 && vm.count("database") == 0 && vm.count("tpm") == 0) {
      if (std::getenv("HOME")) {
        fs::path pibDir(std::getenv("HOME"));
        pibDir /= ".ndn/pib";
        dbDir = pibDir.string();
      }
      else {
        std::cerr << "ERROR: HOME variable is not set" << std::endl;
        return 1;
      }

      tpmLocator = KeyChain::getDefaultTpmLocator();

      if (std::getenv("USER")) {
        owner = std::string(std::getenv("USER"));
      }
      else {
        std::cerr << "ERROR: HOME variable is not set" << std::endl;
        return 1;
      }
    }
    else if (vm.count("owner") == 0 || vm.count("database") == 0 ||
             vm.count("tpm") == 0) {
      std::cerr << description << std::endl;
      return 1;
    }

    Pib pib(face, dbDir, tpmLocator, owner);
    face.processEvents();
  }
  catch (std::runtime_error& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }


  return 0;
}

} // namespace pib
} // namespace ndn

int
main(int argc, char** argv)
{
  ndn::pib::main(argc, argv);
}
