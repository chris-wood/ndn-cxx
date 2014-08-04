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


#ifndef NDN_PIB_LIST_PARAM_HPP
#define NDN_PIB_LIST_PARAM_HPP

#include "../../name.hpp"
#include "pib-common.hpp"

namespace ndn {
namespace pib {

/**
 * @brief ListParam is the abstraction of PIB List parameter.
 *
 *  PibListParam := PIB-LIST-PARAM-TYPE TLV-LENGTH
 *                  PibType    // origin type
 *                  Name?      // origin name
 *
 * @sa http://redmine.named-data.net/projects/ndn-cxx/wiki/PublicKey_Info_Base#List-Parameters
 */

class ListParam : noncopyable
{
public:
  class Error : public Tlv::Error
  {
  public:
    explicit
    Error(const std::string& what)
      : Tlv::Error(what)
    {
    }
  };

  ListParam();

  ListParam(uint32_t originType, const Name& originName);

  uint32_t
  getParamType() const
  {
    return tlv::pib::ListParam;
  }

  std::string
  getParamTypeText() const
  {
    return std::string("list");
  }

  uint32_t
  getOriginType() const
  {
    return m_originType;
  }

  /**
   * @brief Get target name
   *
   * @throws Error if origin name does not exist
   */
  const Name&
  getOriginName() const;

  /// @brief Encode to a wire format or estimate wire format
  template<bool T>
  size_t
  wireEncode(EncodingImpl<T>& block) const;

  /**
   * @brief Encode to a wire format
   *
   * @throws Error if encoding fails
   */
  const Block&
  wireEncode() const;

  /**
   * @brief Decode GetParam from a wire encoded block
   *
   * @throws Error if decoding fails
   */
  void
  wireDecode(const Block& wire);

private:
  uint32_t m_originType;
  Name     m_originName;

  mutable Block m_wire;
};

} // namespace pib
} // namespace ndn



#endif // NDN_PIB_LIST_PARAM_HPP
