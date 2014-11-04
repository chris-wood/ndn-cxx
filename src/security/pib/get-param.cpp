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

#include "get-param.hpp"
#include "encoding/block-helpers.hpp"
#include <boost/lexical_cast.hpp>

namespace ndn {
namespace pib {

static_assert(std::is_base_of<tlv::Error, GetParam::Error>::value,
              "GetParam::Error must inherit from tlv::Error");

GetParam::GetParam()
  : m_targetType(TYPE_USER)
{
}

GetParam::GetParam(uint32_t targetType, const Name& targetName)
  : m_targetType(targetType)
  , m_targetName(targetName)
{
}

const Name&
GetParam::getTargetName() const
{
  if (m_targetType == TYPE_ID || m_targetType == TYPE_KEY || m_targetType == TYPE_CERT)
    return m_targetName;
  else
    throw Error("GetParam::getTargetName: target name does not exist");
}

template<bool T>
size_t
GetParam::wireEncode(EncodingImpl<T>& block) const
{
  size_t totalLength = 0;

  switch (m_targetType) {
  case TYPE_ID:
  case TYPE_KEY:
  case TYPE_CERT:
    {
      totalLength += m_targetName.wireEncode(block);
      break;
    }
  case TYPE_USER:
    break;
  default:
    throw Error("GetParam::wireEncode: unsupported PibType: " +
                boost::lexical_cast<std::string>(m_targetType));
  }

  // Encode Type
  totalLength += prependNonNegativeIntegerBlock(block, tlv::pib::Type, m_targetType);
  totalLength += block.prependVarNumber(totalLength);
  totalLength += block.prependVarNumber(tlv::pib::GetParam);

  return totalLength;
}

template size_t
GetParam::wireEncode<true>(EncodingImpl<true>& block) const;

template size_t
GetParam::wireEncode<false>(EncodingImpl<false>& block) const;

const Block&
GetParam::wireEncode() const
{
  if (m_wire.hasWire())
    return m_wire;

  EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  m_wire = buffer.block();
  return m_wire;
}

void
GetParam::wireDecode(const Block& wire)
{
  if (!wire.hasWire()) {
    throw Error("The supplied block does not contain wire format");
  }

  m_wire = wire;
  m_wire.parse();

  if (m_wire.type() != tlv::pib::GetParam)
    throw Error("Unexpected TLV type when decoding GetParam");

  Block::element_const_iterator it = m_wire.elements_begin();

  // the first block must be Type
  if (it != m_wire.elements_end() && it->type() == tlv::pib::Type) {
    m_targetType = readNonNegativeInteger(*it);
    it++;
  }
  else
    throw Error("GetParam requires the first sub-TLV to be PibType");

  switch (m_targetType) {
  case TYPE_ID:
  case TYPE_KEY:
  case TYPE_CERT:
    {
      if (it != m_wire.elements_end()) {
        // the second block, if exists, must be Name
        m_targetName.wireDecode(*it);
        return;
      }
      else {
        throw Error("GetParam requires the second sub-TLV to be Name");
      }
    }
  case TYPE_USER:
    return;
  default:
    throw Error("GetParam::wireDecode: unsupported PibType: " +
                boost::lexical_cast<std::string>(m_targetType));
  }
}

} // namespace pib
} // namespace ndn
