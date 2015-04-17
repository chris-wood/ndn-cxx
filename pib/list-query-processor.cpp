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

#include "list-query-processor.hpp"
#include "security/pib/pib-encoding.hpp"

#include <boost/lexical_cast.hpp>

namespace ndn {
namespace pib {

using std::string;
using std::vector;

const size_t ListQueryProcessor::LIST_QUERY_LENGTH = 5;

ListQueryProcessor::ListQueryProcessor(PibDb& db)
  : m_db(db)
{
}

std::pair<bool, Block>
ListQueryProcessor::operator()(const Interest& interest)
{
  const Name& interestName = interest.getName();

  // handle pib query: /localhost/pib/[UserName]/list/param
  if (interestName.size() != MIN_PIB_INTEREST_SIZE) {
    // malformed interest, discard
    return std::make_pair(false, Block());
  }

  ListParam param;

  try {
    param.wireDecode(interestName.get(OFFSET_PARAM).blockFromValue());
  }
  catch (const tlv::Error& e) {
    PibError error(ERR_WRONG_PARAM, "error in parsing param: " + string(e.what()));
    return std::make_pair(true, error.wireEncode());
  }

  vector<Name> nameList;
  switch (param.getOriginType()) {
  case TYPE_USER:
    {
      nameList = m_db.listIdentities();
      break;
    }
  case TYPE_ID:
    {
      nameList = m_db.listKeyNamesOfIdentity(param.getOriginName());
      break;
    }
  case TYPE_KEY:
    {
      const Name& keyName = param.getOriginName();
      if (keyName.empty()) {
        PibError error(ERR_WRONG_PARAM,
                       "key name must contain key id component");
        return std::make_pair(true, error.wireEncode());
      }

      nameList = m_db.listCertNamesOfKey(keyName);
      break;
    }
  default:
    {
      PibError error(ERR_WRONG_PARAM,
                     "origin type is not supported: " +
                     boost::lexical_cast<string>(param.getOriginType()));
      return std::make_pair(true, error.wireEncode());
    }
  }

  PibNameList result(nameList);
  return std::make_pair(true, result.wireEncode());
}

} // namespace pib
} // namespace ndn
