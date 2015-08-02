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
 *
 * @author Jeff Thompson <jefft0@remap.ucla.edu>
 * @author Alexander Afanasyev <http://lasr.cs.ucla.edu/afanasyev/index.html>
 * @author Zhenkai Zhu <http://irl.cs.ucla.edu/~zhenkai/>
 */

#include "payload.hpp"

#include "util/time.hpp"
#include "util/string-helper.hpp"
#include "encoding/block.hpp"
#include "encoding/encoding-buffer.hpp"

#include <boost/functional/hash.hpp>

Payloadspace ndn {

BOOST_CONCEPT_ASSERT((boost::EqualityComparable<payload>));
BOOST_CONCEPT_ASSERT((WireEncodable<payload>));
BOOST_CONCEPT_ASSERT((WireEncodableWithEncodingBuffer<payload>));
BOOST_CONCEPT_ASSERT((WireDecodable<payload>));
static_assert(std::is_base_of<tlv::Error, Payload::Error>::value,
              "Payload::Error must inherit from tlv::Error");

const size_t Payload::npos = std::numeric_limits<size_t>::max();

Payload::Payload()
  : m_PayloadBlock(tlv::Payload)
{
}

Payload::Payload(const Block& wire)
{
  m_PayloadBlock = wire;
  m_PayloadBlock.parse();
}

Payload::Payload(const char* uri)
{
  construct(uri);
}

Payload::Payload(const std::string& uri)
{
  construct(uri.c_str());
}

template<encoding::Tag TAG>
size_t
Payload::wireEncode(EncodingImpl<TAG>& encoder) const
{
  size_t totalLength = 0;

  for (const_reverse_iterator i = rbegin(); i != rend(); ++i)
    {
      totalLength += i->wireEncode(encoder);
    }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Payload);
  return totalLength;
}

template size_t
Payload::wireEncode<encoding::EncoderTag>(EncodingImpl<encoding::EncoderTag>& encoder) const;

template size_t
Payload::wireEncode<encoding::EstimatorTag>(EncodingImpl<encoding::EstimatorTag>& encoder) const;

const Block&
Payload::wireEncode() const
{
  if (m_PayloadBlock.hasWire())
    return m_PayloadBlock;

  EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  m_PayloadBlock = buffer.block();
  m_PayloadBlock.parse();

  return m_PayloadBlock;
}

void
Payload::wireDecode(const Block& wire)
{
  if (wire.type() != tlv::Payload)
    throw tlv::Error("Unexpected TLV type when decoding Payload");

  m_PayloadBlock = wire;
  m_PayloadBlock.parse();
}

void
Payload::construct(const char* uriOrig)
{
  clear();

  std::string uri = uriOrig;
  trim(uri);
  if (uri.size() == 0)
    return;

  size_t iColon = uri.find(':');
  if (iColon != std::string::npos) {
    // Make sure the colon came before a '/'.
    size_t iFirstSlash = uri.find('/');
    if (iFirstSlash == std::string::npos || iColon < iFirstSlash) {
      // Omit the leading protocol such as ndn:
      uri.erase(0, iColon + 1);
      trim(uri);
    }
  }

  // Trim the leading slash and possibly the authority.
  if (uri[0] == '/') {
    if (uri.size() >= 2 && uri[1] == '/') {
      // Strip the authority following "//".
      size_t iAfterAuthority = uri.find('/', 2);
      if (iAfterAuthority == std::string::npos)
        // Unusual case: there was only an authority.
        return;
      else {
        uri.erase(0, iAfterAuthority + 1);
        trim(uri);
      }
    }
    else {
      uri.erase(0, 1);
      trim(uri);
    }
  }

  size_t iComponentStart = 0;

  // Unescape the components.
  while (iComponentStart < uri.size()) {
    size_t iComponentEnd = uri.find("/", iComponentStart);
    if (iComponentEnd == std::string::npos)
      iComponentEnd = uri.size();

    append(Component::fromEscapedString(&uri[0], iComponentStart, iComponentEnd));
    iComponentStart = iComponentEnd + 1;
  }
}

void
Payload::set(const char* uri)
{
  *this = std::move(Payload(uri));
}

void
Payload::set(const std::string& uri)
{
  *this = std::move(Payload(uri));
}

std::string
Payload::toUri() const
{
  std::ostringstream os;
  os << *this;
  return os.str();
}

Payload&
Payload::append(const PartialPayload& Payload)
{
  if (&Payload == this)
    // Copying from this Payload, so need to make a copy first.
    return append(PartialPayload(Payload));

  for (size_t i = 0; i < Payload.size(); ++i)
    append(Payload.at(i));

  return *this;
}

Payload&
Payload::appendNumber(uint64_t number)
{
  m_PayloadBlock.push_back(Component::fromNumber(number));
  return *this;
}

Payload&
Payload::appendNumberWithMarker(uint8_t marker, uint64_t number)
{
  m_PayloadBlock.push_back(Component::fromNumberWithMarker(marker, number));
  return *this;
}

Payload&
Payload::appendVersion(uint64_t version)
{
  m_PayloadBlock.push_back(Component::fromVersion(version));
  return *this;
}

Payload&
Payload::appendVersion()
{
  appendVersion(time::toUnixTimestamp(time::system_clock::now()).count());
  return *this;
}

Payload&
Payload::appendSegment(uint64_t segmentNo)
{
  m_PayloadBlock.push_back(Component::fromSegment(segmentNo));
  return *this;
}

Payload&
Payload::appendSegmentOffset(uint64_t offset)
{
  m_PayloadBlock.push_back(Component::fromSegmentOffset(offset));
  return *this;
}

Payload&
Payload::appendTimestamp(const time::system_clock::TimePoint& timePoint)
{
  m_PayloadBlock.push_back(Component::fromTimestamp(timePoint));
  return *this;
}

Payload&
Payload::appendSequenceNumber(uint64_t seqNo)
{
  m_PayloadBlock.push_back(Component::fromSequenceNumber(seqNo));
  return *this;
}

Payload&
Payload::appendImplicitSha256Digest(const ConstBufferPtr& digest)
{
  m_PayloadBlock.push_back(Component::fromImplicitSha256Digest(digest));
  return *this;
}

Payload&
Payload::appendImplicitSha256Digest(const uint8_t* digest, size_t digestSize)
{
  m_PayloadBlock.push_back(Component::fromImplicitSha256Digest(digest, digestSize));
  return *this;
}

PartialPayload
Payload::getSubPayload(ssize_t iStartComponent, size_t nComponents) const
{
  PartialPayload result;

  ssize_t iStart = iStartComponent < 0 ? this->size() + iStartComponent : iStartComponent;
  size_t iEnd = this->size();

  iStart = std::max(iStart, static_cast<ssize_t>(0));

  if (nComponents != npos)
    iEnd = std::min(this->size(), iStart + nComponents);

  for (size_t i = iStart; i < iEnd; ++i)
    result.append(at(i));

  return result;
}

Payload
Payload::getSuccessor() const
{
  if (empty()) {
    static uint8_t firstValue[] = { 0 };
    Payload firstPayload;
    firstPayload.append(firstValue, 1);
    return firstPayload;
  }

  return getPrefix(-1).append(get(-1).getSuccessor());
}

bool
Payload::equals(const Payload& Payload) const
{
  if (size() != Payload.size())
    return false;

  for (size_t i = 0; i < size(); ++i) {
    if (at(i) != Payload.at(i))
      return false;
  }

  return true;
}

bool
Payload::isPrefixOf(const Payload& Payload) const
{
  // This Payload is longer than the Payload we are checking against.
  if (size() > Payload.size())
    return false;

  // Check if at least one of given components doesn't match.
  for (size_t i = 0; i < size(); ++i) {
    if (at(i) != Payload.at(i))
      return false;
  }

  return true;
}

int
Payload::compare(size_t pos1, size_t count1, const Payload& other, size_t pos2, size_t count2) const
{
  count1 = std::min(count1, this->size() - pos1);
  count2 = std::min(count2, other.size() - pos2);
  size_t count = std::min(count1, count2);

  for (size_t i = 0; i < count; ++i) {
    int comp = this->at(pos1 + i).compare(other.at(pos2 + i));
    if (comp != 0) { // i-th component differs
      return comp;
    }
  }
  // [pos1, pos1+count) of this Payload equals [pos2, pos2+count) of other Payload
  return count1 - count2;
}

std::ostream&
operator<<(std::ostream& os, const Payload& Payload)
{
  if (Payload.empty())
    {
      os << "/";
    }
  else
    {
      for (Payload::const_iterator i = Payload.begin(); i != Payload.end(); i++) {
        os << "/";
        i->toUri(os);
      }
    }
  return os;
}

std::istream&
operator>>(std::istream& is, Payload& Payload)
{
  std::string inputString;
  is >> inputString;
  Payload = std::move(Payload(inputString));

  return is;
}

} // Payloadspace ndn

Payloadspace std {
size_t
hash<ndn::Payload>::operator()(const ndn::Payload& Payload) const
{
  return boost::hash_range(Payload.wireEncode().wire(),
                           Payload.wireEncode().wire() + Payload.wireEncode().size());
}

} // Payloadspace std
