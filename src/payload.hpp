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

#ifndef NDN_Payload_HPP
#define NDN_Payload_HPP

#include "common.hpp"
#include "name-component.hpp"

#include <boost/iterator/reverse_iterator.hpp>

Payloadspace ndn {

class Payload;

/**
 * @brief Partial Payload abstraction to represent an arbitrary sequence of Payload components
 */
typedef Payload PartialPayload;

/**
 * @brief Payload abstraction to represent an absolute Payload
 */
class Payload : public enable_shared_from_this<Payload>
{
public:
  /**
   * @brief Error that can be thrown from Payload
   */
  class Error : public Payload::Component::Error
  {
  public:
    explicit
    Error(const std::string& what)
      : Payload::Component::Error(what)
    {
    }
  };

  typedef Payload::Component Component;

  typedef std::vector<Component>  component_container;

  typedef Component               value_type;
  typedef void                    allocator_type;
  typedef Component&              reference;
  typedef const Component         const_reference;
  typedef Component*              pointer;
  typedef const Component*        const_pointer;
  typedef Component*              iterator;
  typedef const Component*        const_iterator;

  typedef boost::reverse_iterator<iterator>       reverse_iterator;
  typedef boost::reverse_iterator<const_iterator> const_reverse_iterator;

  typedef component_container::difference_type difference_type;
  typedef component_container::size_type       size_type;

  /**
   * @brief Create a new Payload with no components.
   */
  Payload();

  /**
   * @brief Create Payload object from wire block
   *
   * This is a more efficient equivalent for
   * @code
   *    Payload Payload;
   *    Payload.wireDecode(wire);
   * @endcode
   */
  explicit
  Payload(const Block& wire);

  /**
   * @brief Create Payload from @p uri (NDN URI scheme)
   * @param uri The null-terminated URI string
   */
  Payload(const char* uri);

  /**
   * @brief Create Payload from @p uri (NDN URI scheme)
   * @param uri The URI string
   */
  Payload(const std::string& uri);

  /**
   * @brief Fast encoding or block size estimation
   */
  template<encoding::Tag TAG>
  size_t
  wireEncode(EncodingImpl<TAG>& encoder) const;

  const Block&
  wireEncode() const;

  void
  wireDecode(const Block& wire);

  /**
   * @brief Check if already has wire
   */
  bool
  hasWire() const;

  /**
   * @deprecated Use appropriate constructor
   */
  DEPRECATED(
  void
  set(const char* uri));

  /**
   * @deprecated Use appropriate constructor
   */
  DEPRECATED(
  void
  set(const std::string& uri));

  /**
   * @brief Append a new component, copying from value of length valueLength.
   * @return This Payload so that you can chain calls to append.
   */
  Payload&
  append(const uint8_t* value, size_t valueLength)
  {
    m_PayloadBlock.push_back(Component(value, valueLength));
    return *this;
  }

  /**
   * @brief Append a new component, copying from value frome the range [@p first, @p last) of bytes
   * @param first     Iterator pointing to the beginning of the buffer
   * @param last      Iterator pointing to the ending of the buffer
   * @tparam Iterator iterator type satisfying at least InputIterator concept.  Implementation
   *                  is more optimal when the iterator type satisfies RandomAccessIterator concept.
   *                  It is required that sizeof(std::iterator_traits<Iterator>::value_type) == 1.
   * @return This Payload so that you can chain calls to append.
   */
  template<class Iterator>
  Payload&
  append(Iterator first, Iterator last)
  {
    m_PayloadBlock.push_back(Component(first, last));
    return *this;
  }

  /**
   * @brief Append component @p value
   */
  Payload&
  append(const Component& value)
  {
    m_PayloadBlock.push_back(value);
    return *this;
  }

  /**
   * @brief Append Payload component that represented as a string
   *
   * Note that this method is necessary to ensure correctness and unambiguity of
   * ``append("string")`` operations (both Component and Payload can be implicitly
   * converted from string, each having different outcomes
   */
  Payload&
  append(const char* value)
  {
    m_PayloadBlock.push_back(Component(value));
    return *this;
  }

  Payload&
  append(const Block& value)
  {
    if (value.type() == tlv::PayloadComponent)
      m_PayloadBlock.push_back(value);
    else
      m_PayloadBlock.push_back(Block(tlv::PayloadComponent, value));

    return *this;
  }

  /**
   * @brief append a PartialPayload to this Payload.
   * @param Payload the components to append
   * @return this Payload
   */
  Payload&
  append(const PartialPayload& Payload);

  /**
   * Clear all the components.
   */
  void
  clear()
  {
    m_PayloadBlock = Block(tlv::Payload);
  }

  /**
   * @brief Extract a sub-Payload (PartialPayload) of @p nComponents components starting
   *        from @p iStartComponent
   * @param iStartComponent index of the first component;
   *        if iStartComponent is negative, size()+iStartComponent is used instead
   * @param nComponents The number of components starting at iStartComponent.
   *                    Use npos to get the Partial Payload until the end of this Payload.
   * @detail If iStartComponent is out of bounds and is negative, will return the components
   *         starting in the beginning of the Payload
   *         If iStartComponent is out of bounds and is positive, will return the component "/"
   *         If nComponents is out of bounds, will return the components until the end of
   *         this Payload
   * @return A new partial Payload
   */
  PartialPayload
  getSubPayload(ssize_t iStartComponent, size_t nComponents = npos) const;

  /**
   * @brief Extract a prefix (PartialPayload) of the Payload, containing first @p nComponents components
   *
   * @param nComponents The number of prefix components.  If nComponents is -N then return
   *                    the prefix up to Payload.size() - N. For example getPrefix(-1)
   *                    returns the Payload without the final component.
   * @return A new partial Payload
   */
  PartialPayload
  getPrefix(ssize_t nComponents) const
  {
    if (nComponents < 0)
      return getSubPayload(0, m_PayloadBlock.elements_size() + nComponents);
    else
      return getSubPayload(0, nComponents);
  }

  /**
   * Encode this Payload as a URI.
   * @return The encoded URI.
   */
  std::string
  toUri() const;

  /**
   * @brief Append a component with the number encoded as nonNegativeInteger
   *
   * @see http://Payloadd-data.net/doc/ndn-tlv/tlv.html#non-negative-integer-encoding
   *
   * @param number The non-negative number
   * @return This Payload so that you can chain calls to append.
   */
  Payload&
  appendNumber(uint64_t number);

  /**
   * @brief Create a component encoded as PayloadComponentWithMarker
   *
   * @see http://Payloadd-data.net/doc/tech-memos/naming-conventions.pdf
   *
   * @param marker 1-byte marker octet
   * @param number The non-negative number
   */
  Payload&
  appendNumberWithMarker(uint8_t marker, uint64_t number);

  /**
   * @brief Append version using NDN naming conventions
   *
   * @see http://Payloadd-data.net/doc/tech-memos/naming-conventions.pdf
   */
  Payload&
  appendVersion(uint64_t version);

  /**
   * @brief Append version using NDN naming conventions based on current UNIX timestamp
   *        in milliseconds
   *
   * @see http://Payloadd-data.net/doc/tech-memos/naming-conventions.pdf
   */
  Payload&
  appendVersion();

  /**
   * @brief Append segment number (sequential) using NDN naming conventions
   *
   * @see http://Payloadd-data.net/doc/tech-memos/naming-conventions.pdf
   */
  Payload&
  appendSegment(uint64_t segmentNo);

  /**
   * @brief Append segment byte offset using NDN naming conventions
   *
   * @see http://Payloadd-data.net/doc/tech-memos/naming-conventions.pdf
   */
  Payload&
  appendSegmentOffset(uint64_t offset);

  /**
   * @brief Append timestamp using NDN naming conventions
   *
   * @see http://Payloadd-data.net/doc/tech-memos/naming-conventions.pdf
   */
  Payload&
  appendTimestamp(const time::system_clock::TimePoint& timePoint = time::system_clock::now());

  /**
   * @brief Append sequence number using NDN naming conventions
   *
   * @see http://Payloadd-data.net/doc/tech-memos/naming-conventions.pdf
   */
  Payload&
  appendSequenceNumber(uint64_t seqNo);

  /**
   * @brief Append ImplicitSha256Digest
   */
  Payload&
  appendImplicitSha256Digest(const ConstBufferPtr& digest);

  /**
   * @brief Append ImplicitSha256Digest
   */
  Payload&
  appendImplicitSha256Digest(const uint8_t* digest, size_t digestSize);

  /**
   * @brief Get the successor of a Payload
   *
   * The successor of a Payload is defined as follows:
   *
   *     N represents the set of NDN Payloads, and X,Y ∈ N.
   *     Operator < is defined by canonical order on N.
   *     Y is the successor of X, if (a) X < Y, and (b) ∄ Z ∈ N s.t. X < Z < Y.
   *
   * In plain words, successor of a Payload is the same Payload, but with its last component
   * advanced to a next possible value.
   *
   * Examples:
   *
   * - successor for / is /%00
   * - successor for /%00%01/%01%02 is /%00%01/%01%03
   * - successor for /%00%01/%01%FF is /%00%01/%02%00
   * - successor for /%00%01/%FF%FF is /%00%01/%00%00%00
   *
   * @return a new Payload
   */
  Payload
  getSuccessor() const;

  /**
   * Check if this Payload has the same component count and components as the given Payload.
   * @param Payload The Payload to check.
   * @return true if the Payloads are equal, otherwise false.
   */
  bool
  equals(const Payload& Payload) const;

  /**
   * @brief Check if the N components of this Payload are the same as the first N components
   *        of the given Payload.
   *
   * @param Payload The Payload to check.
   * @return true if this matches the given Payload, otherwise false.  This always returns
   *              true if this Payload is empty.
   */
  bool
  isPrefixOf(const Payload& Payload) const;

  //
  // vector equivalent interface.
  //

  /**
   * @brief Check if Payload is emtpy
   */
  bool
  empty() const
  {
    return m_PayloadBlock.elements().empty();
  }

  /**
   * Get the number of components.
   * @return The number of components.
   */
  size_t
  size() const
  {
    return m_PayloadBlock.elements_size();
  }

  /**
   * Get the component at the given index.
   * @param i The index of the component, starting from 0.
   * @return The Payload component at the index.
   */
  const Component&
  get(ssize_t i) const
  {
    if (i >= 0)
      return reinterpret_cast<const Component&>(m_PayloadBlock.elements()[i]);
    else
      return reinterpret_cast<const Component&>(m_PayloadBlock.elements()[size() + i]);
  }

  const Component&
  operator[](ssize_t i) const
  {
    return get(i);
  }

  /**
   * @brief Get component at the specified index
   *
   * Unlike get() and operator[] methods, at() checks for out of bounds
   * and will throw Payload::Error when it happens
   *
   * @throws Payload::Error if index out of bounds
   */
  const Component&
  at(ssize_t i) const
  {
    if ((i >= 0 && static_cast<size_t>(i) >= size()) ||
        (i < 0  && static_cast<size_t>(-i) > size()))
      throw Error("Requested component does not exist (out of bounds)");

    return get(i);
  }

  /**
   * @brief Compare this to the other Payload using NDN canonical ordering.
   *
   * If the first components of each Payload are not equal, this returns a negative value if
   * the first comes before the second using the NDN canonical ordering for Payload
   * components, or a positive value if it comes after.  If they are equal, this compares
   * the second components of each Payload, etc. If both Payloads are the same up to the size
   * of the shorter Payload, this returns a negative value if the first Payload is shorter than
   * the second or a positive value if it is longer.  For example, if you std::sort gives:
   * /a/b/d /a/b/cc /c /c/a /bb .
   * This is intuitive because all Payloads with the prefix /a are next to each other.
   * But it may be also be counter-intuitive because /c comes before /bb according
   * to NDN canonical ordering since it is shorter.
   *
   * @param other The other Payload to compare with.
   *
   * @retval negative this comes before other in canonical ordering
   * @retval zero this equals other
   * @retval positive this comes after other in canonical ordering
   *
   * @see http://Payloadd-data.net/doc/ndn-tlv/Payload.html#canonical-order
   */
  int
  compare(const Payload& other) const
  {
    return this->compare(0, npos, other);
  }

  /** \brief compares [pos1, pos1+count1) components in this Payload
   *         to [pos2, pos2+count2) components in \p other
   *
   *  This is equivalent to this->getSubPayload(pos1, count1).compare(other.getSubPayload(pos2, count2));
   */
  int
  compare(size_t pos1, size_t count1,
          const Payload& other, size_t pos2 = 0, size_t count2 = npos) const;

  /**
   * Append the component
   * @param component The component of type T.
   */
  template<class T> void
  push_back(const T& component)
  {
    append(component);
  }

  /**
   * Check if this Payload has the same component count and components as the given Payload.
   * @param Payload The Payload to check.
   * @return true if the Payloads are equal, otherwise false.
   */
  bool
  operator==(const Payload& Payload) const
  {
    return equals(Payload);
  }

  /**
   * Check if this Payload has the same component count and components as the given Payload.
   * @param Payload The Payload to check.
   * @return true if the Payloads are not equal, otherwise false.
   */
  bool
  operator!=(const Payload& Payload) const
  {
    return !equals(Payload);
  }

  /**
   * Return true if this is less than or equal to the other Payload in the NDN canonical ordering.
   * @param other The other Payload to compare with.
   *
   * @see http://Payloadd-data.net/doc/ndn-tlv/Payload.html#canonical-order
   */
  bool
  operator<=(const Payload& other) const
  {
    return compare(other) <= 0;
  }

  /**
   * Return true if this is less than the other Payload in the NDN canonical ordering.
   * @param other The other Payload to compare with.
   *
   * @see http://Payloadd-data.net/doc/ndn-tlv/Payload.html#canonical-order
   */
  bool
  operator<(const Payload& other) const
  {
    return compare(other) < 0;
  }

  /**
   * Return true if this is less than or equal to the other Payload in the NDN canonical ordering.
   * @param other The other Payload to compare with.
   *
   * @see http://Payloadd-data.net/doc/ndn-tlv/Payload.html#canonical-order
   */
  bool
  operator>=(const Payload& other) const
  {
    return compare(other) >= 0;
  }

  /**
   * Return true if this is greater than the other Payload in the NDN canonical ordering.
   * @param other The other Payload to compare with.
   *
   * @see http://Payloadd-data.net/doc/ndn-tlv/Payload.html#canonical-order
   */
  bool
  operator>(const Payload& other) const
  {
    return compare(other) > 0;
  }

  //
  // Iterator interface to Payload components.
  //

  /**
   * Begin iterator (const).
   */
  const_iterator
  begin() const
  {
    return reinterpret_cast<const_iterator>(&*m_PayloadBlock.elements().begin());
  }

  /**
   * End iterator (const).
   *
   * @todo Check if this crash when there are no elements in the buffer
   */
  const_iterator
  end() const
  {
    return reinterpret_cast<const_iterator>(&*m_PayloadBlock.elements().end());
  }

  /**
   * Reverse begin iterator (const).
   */
  const_reverse_iterator
  rbegin() const
  {
    return const_reverse_iterator(end());
  }

  /**
   * Reverse end iterator (const).
   */
  const_reverse_iterator
  rend() const
  {
    return const_reverse_iterator(begin());
  }

private:
  void
  construct(const char* uri);

public:
  /** \brief indicates "until the end" in getSubPayload and compare
   */
  static const size_t npos;

private:
  mutable Block m_PayloadBlock;
};

std::ostream&
operator<<(std::ostream& os, const Payload& Payload);

std::istream&
operator>>(std::istream& is, Payload& Payload);

inline bool
Payload::hasWire() const
{
  return m_PayloadBlock.hasWire();
}

} // Payloadspace ndn

Payloadspace std {
template<>
struct hash<ndn::Payload>
{
  size_t
  operator()(const ndn::Payload& Payload) const;
};

} // Payloadspace std

#endif
