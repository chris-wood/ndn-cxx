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

#ifndef NDN_PIB_CERT_PUBLISHER_HPP
#define NDN_PIB_CERT_PUBLISHER_HPP

#include "pib-db.hpp"

#include "face.hpp"
#include "util/in-memory-storage-persistent.hpp"

namespace ndn {
namespace pib {

/// @brief implements the certificate publisher
class CertPublisher : noncopyable
{
public:
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

  /**
   * @brief Constructor
   *
   * @param face The face pib used to receive queries and serve certificates.
   * @param pibDb Database which holds the certificates.
   */
  CertPublisher(Face& face, PibDb& pibDb);

  ~CertPublisher();

private:
  void
  startPublishAll();

  /**
   * @brief add an interest filter for the certificate
   */
  void
  registerCertPrefix(const Name& certName);

  void
  processInterest(const InterestFilter& interestFilter,
                  const Interest& interest);

  void
  startPublish(const Name& certName);

  /**
   * @brief callback when a certificate is deleted
   *
   * The method will remove the cert from in-memory storage
   * and also unset interest filter if the removed cert
   * is the only one with the registered prefix.
   *
   * @param certName removed certificate name
   */
  void
  stopPublish(const Name& certName);

private:
  Face& m_face;
  PibDb& m_db;
  util::InMemoryStoragePersistent m_responseCache;
  std::map<Name, const RegisteredPrefixId*> m_registeredPrefixes;

  util::signal::ScopedConnection m_certDeletedConnection;
  util::signal::ScopedConnection m_certInsertedConnection;
};

} // namespace pib
} // namespace ndn

#endif // NDN_PIB_CERT_PUBLISHER_HPP
