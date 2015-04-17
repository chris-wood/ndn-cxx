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

#ifndef NDN_PIB_LIST_QUERY_PROCESSOR_HPP
#define NDN_PIB_LIST_QUERY_PROCESSOR_HPP

#include "pib-db.hpp"
#include "interest.hpp"
#include "security/pib/list-param.hpp"
#include <utility>

namespace ndn {
namespace pib {

class ListQueryProcessor : noncopyable
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
   * @param db The pib database.
   */
  explicit
  ListQueryProcessor(PibDb& db);

  std::pair<bool, Block>
  operator()(const Interest& interest);

private:
  static const size_t LIST_QUERY_LENGTH;

  const PibDb&  m_db;
};

} // namespace pib
} // namespace ndn

#endif // NDN_PIB_LIST_QUERY_PROCESSOR_HPP
