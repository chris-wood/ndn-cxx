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

#ifndef NDN_PIB_KEY_CACHE_HPP
#define NDN_PIB_KEY_CACHE_HPP

#include "name.hpp"
#include "util/time.hpp"
#include "security/public-key.hpp"

#include <stack>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/key_extractors.hpp>

namespace ndn {
namespace pib {

struct KeyCacheEntry
{
  KeyCacheEntry(const Name& name, shared_ptr<PublicKey> key);

  Name name;
  shared_ptr<PublicKey> key;
};

class byName;
class byUsedTime;

typedef boost::multi_index::multi_index_container<
  KeyCacheEntry,
  boost::multi_index::indexed_by<
    boost::multi_index::hashed_unique<
      boost::multi_index::tag<byName>,
      boost::multi_index::member<KeyCacheEntry, Name, &KeyCacheEntry::name>,
      std::hash<Name>
    >,

    boost::multi_index::sequenced<
      boost::multi_index::tag<byUsedTime>
    >
  >
> KeyContainer;

class KeyCache : noncopyable
{
public:
  explicit
  KeyCache(size_t capacity = getDefaultCapacity());

  void
  insert(const Name& name, shared_ptr<PublicKey> key);

  shared_ptr<PublicKey>
  find(const Name& name) const;

  void
  erase(const Name& name);

  size_t
  size() const;

private:
  static size_t
  getDefaultCapacity()
  {
    return 100;
  }

  void
  evictKey();

  void
  adjustLru(KeyContainer::iterator it) const;

  void
  freeEntry(KeyContainer::iterator it);

private:
  size_t m_capacity;
  mutable KeyContainer m_keys;
};

} // namespace pib
} // namespace ndn

#endif // NDN_PIB_KEY_CACHE_HPP
