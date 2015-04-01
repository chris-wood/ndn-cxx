/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2015 Regents of the University of California.
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

#include "pib/cert-publisher.hpp"
#include "identity-management-time-fixture.hpp"
#include "util/dummy-client-face.hpp"

#include <boost/filesystem.hpp>

#include "boost-test.hpp"

namespace ndn {
namespace pib {
namespace tests {

class CertPublisherFixture : public ndn::security::IdentityManagementTimeFixture
{
public:
  CertPublisherFixture()
    : tmpPath(boost::filesystem::path(TEST_CONFIG_PATH) / "DbTest")
    , db(tmpPath.c_str())
    , face(util::makeDummyClientFace(io, {true, true}))
  {
  }

  ~CertPublisherFixture()
  {
    boost::filesystem::remove_all(tmpPath);
  }

  boost::filesystem::path tmpPath;
  PibDb db;
  shared_ptr<util::DummyClientFace> face;
};

BOOST_FIXTURE_TEST_SUITE(TestCertPublisher, CertPublisherFixture)

BOOST_AUTO_TEST_CASE(Basic)
{
  // Initialize id1
  Name id1("/test/identity");
  addIdentity(id1);
  Name certName111 = m_keyChain.getDefaultCertificateNameForIdentity(id1);
  shared_ptr<IdentityCertificate> cert111 = m_keyChain.getCertificate(certName111);
  Name keyName11 = cert111->getPublicKeyName();

  advanceClocks(time::milliseconds(100));
  shared_ptr<IdentityCertificate> cert112 = m_keyChain.selfSign(keyName11);
  Name certName112 = cert112->getName();

  CertPublisher certPublisher(*face, db);

  // Add a certificate
  db.addCertificate(*cert111);
  advanceClocks(time::milliseconds(2), 50);

  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 0);
  auto interest111 = make_shared<Interest>(cert111->getName().getPrefix(-1));
  face->receive(*interest111);
  advanceClocks(time::milliseconds(2), 50);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 1);
  BOOST_CHECK(face->sentDatas[0].wireEncode() == cert111->wireEncode());
  face->sentDatas.clear();

  // Add another certificate
  db.addCertificate(*cert112);
  advanceClocks(time::milliseconds(2), 50);

  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 0);
  auto interest112 = make_shared<Interest>(cert112->getName().getPrefix(-1));
  face->receive(*interest112);
  advanceClocks(time::milliseconds(2), 50);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 1);
  BOOST_CHECK(face->sentDatas[0].wireEncode() == cert111->wireEncode());
  face->sentDatas.clear();

  Exclude exclude;
  exclude.excludeOne(cert111->getName().get(-1));
  interest112->setExclude(exclude);
  face->receive(*interest112);
  advanceClocks(time::milliseconds(2), 50);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 1);
  BOOST_CHECK(face->sentDatas[0].wireEncode() == cert112->wireEncode());
  face->sentDatas.clear();

  // delete a certificate
  db.deleteCertificate(certName112);
  face->receive(*interest112);
  advanceClocks(time::milliseconds(2), 50);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 0);

  face->receive(*interest111);
  advanceClocks(time::milliseconds(2), 50);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 1);
  BOOST_CHECK(face->sentDatas[0].wireEncode() == cert111->wireEncode());
  face->sentDatas.clear();

  // delete another certificate
  db.deleteCertificate(certName111);
  face->receive(*interest112);
  advanceClocks(time::milliseconds(2), 50);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 0);

  face->receive(*interest111);
  advanceClocks(time::milliseconds(2), 50);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 0);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace pib
} // namespace ndn
