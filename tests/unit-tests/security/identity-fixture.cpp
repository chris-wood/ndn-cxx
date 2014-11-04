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

#include "security/key-chain.hpp"

#include "boost-test.hpp"

namespace ndn {
namespace security {

class IdentityFixture
{
public:
  IdentityFixture()
  {
    // initialize KeyChain from TEST_HOME
    if (std::getenv("TEST_HOME"))
      m_HOME = std::getenv("TEST_HOME");
    setenv("TEST_HOME", "tests/unit-tests/security/config-file-home", 1);

    KeyChain keyChain("sqlite3", "file");

    // save the old default identity
    try {
      m_oldDefaultIdentity = keyChain.getDefaultIdentity();
      m_hasOldDefaultIdentity = true;
    }
    catch (SecPublicInfo::Error& e) {
      m_hasOldDefaultIdentity = false;
    }

    m_newIdentity.set("/ndn-cxx-test-identity");
    m_newIdentity.appendVersion();

    // create the new identity and self-signed certificate
    keyChain.createIdentity(m_newIdentity);

    // set the new identity as default identity,
    // and the corresponding certificate becomes the default certificate
    keyChain.setDefaultIdentity(m_newIdentity);
  }

  ~IdentityFixture()
  {
    KeyChain keyChain("sqlite3", "file");

    // recover the old default setting
    if (m_hasOldDefaultIdentity) {
      keyChain.setDefaultIdentity(m_oldDefaultIdentity);
    }

    // remove the temporarily created identity and certificates
    // XXX This has no effect if oldDefaultIdentity doesn't exist.
    //     newIdentity would be kept as default.
    keyChain.deleteIdentity(m_newIdentity);

    if (!m_HOME.empty())
      setenv("TEST_HOME", m_HOME.c_str(), 1);
    else
      unsetenv("TEST_HOME");
  }

private:
  std::string m_HOME;

  bool m_hasOldDefaultIdentity;
  Name m_oldDefaultIdentity;
  Name m_newIdentity;
};

BOOST_GLOBAL_FIXTURE(IdentityFixture)

} // namespace security
} // namespace ndn
