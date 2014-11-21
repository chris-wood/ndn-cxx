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

#ifndef NDN_PIB_PIB_VALIDATOR_HPP
#define NDN_PIB_PIB_VALIDATOR_HPP

#include "security/validator.hpp"
#include "pib-db.hpp"
#include "key-cache.hpp"
#include <unordered_map>

namespace ndn {
namespace pib {


/*
 * @brief The validator to verify the command interests to PIB service
 *
 * @sa http://redmine.named-data.net/projects/ndn-cxx/wiki/PublicKey_Info_Base
 */
class PibValidator : public Validator
{
  struct UserKeyCache;
public:
  explicit
  PibValidator(const PibDb& pibDb,
               size_t maxCacheSize = 1000);

NDN_CXX_PUBLIC_WITH_TESTS_ELSE_PROTECTED:
  void
  handleUserChange(const std::string& user);

  void
  handleKeyDeletion(const std::string& user, const Name& identity, const name::Component& keyId);

protected:
  virtual void
  checkPolicy(const Interest& interest,
              int nSteps,
              const OnInterestValidated& onValidated,
              const OnInterestValidationFailed& onValidationFailed,
              std::vector<shared_ptr<ValidationRequest>>& nextSteps);

  virtual void
  checkPolicy(const Data& data,
              int nSteps,
              const OnDataValidated& onValidated,
              const OnDataValidationFailed& onValidationFailed,
              std::vector<shared_ptr<ValidationRequest>>& nextSteps);

  shared_ptr<UserKeyCache>
  getRootKeyCache();

private:
  struct UserKeyCache : noncopyable
  {
    shared_ptr<IdentityCertificate> mgmtCertificate;

    // non-management keys
    KeyCache regularKeys;
  };

  typedef std::unordered_map<std::string, shared_ptr<UserKeyCache>> PublicKeyCache;

  const PibDb& m_db;
  PublicKeyCache m_keyCache;
};

} // namespace pib
} // namespace ndn

#endif // NDN_PIB_PIB_VALIDATOR_HPP
