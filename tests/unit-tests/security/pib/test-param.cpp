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

#include "security/pib/get-param.hpp"
#include "security/pib/default-param.hpp"
#include "security/pib/list-param.hpp"
#include "security/pib/update-param.hpp"
#include "security/pib/delete-param.hpp"
#include "security/pib/pib-encoding.hpp"

#include "boost-test.hpp"

namespace ndn {
namespace pib {
namespace test {

BOOST_AUTO_TEST_SUITE(PibTestParam)

BOOST_AUTO_TEST_CASE(GetParamEndec)
{
  const uint8_t paramData1[] = {
    0x80, 0x10, // GetParam
      0x97, 0x01, // Type
        0x02, // KEY
      0x07, 0x0b, // Name "/test/key"
        0x08, 0x04,
          0x74, 0x65, 0x73, 0x74,
        0x08, 0x03,
          0x6b, 0x65, 0x79
  };

  Block paramBlock1(paramData1, sizeof(paramData1));
  GetParam param1;
  BOOST_REQUIRE_NO_THROW(param1.wireDecode(paramBlock1));

  BOOST_CHECK_EQUAL(param1.getTargetType(), TYPE_KEY);
  BOOST_CHECK_EQUAL(param1.getTargetName(), Name("/test/key"));

  GetParam param2(TYPE_KEY, Name("/test/key"));
  Block paramBlock2 = param2.wireEncode();
  BOOST_CHECK_EQUAL_COLLECTIONS(paramBlock2.wire(),
                                paramBlock2.wire() + paramBlock2.size(),
                                paramBlock1.wire(),
                                paramBlock1.wire() + paramBlock1.size());

  const uint8_t paramData3[] = {
    0x80, 0x03, // GetParam
      0x97, 0x01, // Type
        0x00, // USER
  };
  Block paramBlock3(paramData3, sizeof(paramData3));
  GetParam param3;
  BOOST_REQUIRE_NO_THROW(param3.wireDecode(paramBlock3));

  BOOST_CHECK_EQUAL(param3.getTargetType(), TYPE_USER);
  BOOST_CHECK_THROW(param3.getTargetName(), tlv::Error);

  GetParam param4;
  Block paramBlock4 = param4.wireEncode();
  BOOST_CHECK_EQUAL_COLLECTIONS(paramBlock4.wire(),
                                paramBlock4.wire() + paramBlock4.size(),
                                paramBlock3.wire(),
                                paramBlock3.wire() + paramBlock3.size());
}

BOOST_AUTO_TEST_CASE(GetParamEndecError)
{
  GetParam wrongParam(TYPE_DEFAULT, Name("/test/key"));
  BOOST_CHECK_THROW(wrongParam.wireEncode(), tlv::Error);

  GetParam param;

  const uint8_t wrongParamData1[] = {
    0x81, 0x03, // GetParam (Wrong)
      0x97, 0x01, // Type
        0x00, // USER
  };
  Block wrongParamBlock1(wrongParamData1, sizeof(wrongParamData1));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock1), tlv::Error);

  const uint8_t wrongParamData2[] = {
    0x80, 0x03, // GetParam
      0x91, 0x01, // Type (Wrong)
        0x00, // USER
  };
  Block wrongParamBlock2(wrongParamData2, sizeof(wrongParamData2));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock2), tlv::Error);

  const uint8_t wrongParamData3[] = {
    0x80, 0x10, // GetParam
      0x97, 0x01, // Type
        0x02, // KEY
      0x08, 0x0b, // Name "/test/key" (Wrong)
        0x08, 0x04,
          0x74, 0x65, 0x73, 0x74,
        0x08, 0x03,
          0x6b, 0x65, 0x79
  };
  Block wrongParamBlock3(wrongParamData3, sizeof(wrongParamData3));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock3), tlv::Error);
}

BOOST_AUTO_TEST_CASE(DefaultParamEndec)
{
  const uint8_t paramData1[] = {
    0x81, 0x13, // DefaultParam
      0x97, 0x01, // Target Type
        0x03, // CERT
      0x97, 0x01, // Origin Type
        0x02, // KEY
      0x07, 0x0b, // Name "/test/key"
        0x08, 0x04,
          0x74, 0x65, 0x73, 0x74,
        0x08, 0x03,
          0x6b, 0x65, 0x79
  };

  Block paramBlock1(paramData1, sizeof(paramData1));
  DefaultParam param1;
  BOOST_REQUIRE_NO_THROW(param1.wireDecode(paramBlock1));

  BOOST_CHECK_EQUAL(param1.getTargetType(), TYPE_CERT);
  BOOST_CHECK_EQUAL(param1.getOriginType(), TYPE_KEY);
  BOOST_CHECK_EQUAL(param1.getOriginName(), Name("/test/key"));

  DefaultParam param2(TYPE_CERT, TYPE_KEY, Name("/test/key"));
  Block paramBlock2 = param2.wireEncode();
  BOOST_CHECK_EQUAL_COLLECTIONS(paramBlock2.wire(),
                                paramBlock2.wire() + paramBlock2.size(),
                                paramBlock1.wire(),
                                paramBlock1.wire() + paramBlock1.size());

  const uint8_t paramData3[] = {
    0x81, 0x06, // DefaultParam
      0x97, 0x01, // Target Type
        0x03, // CERT
      0x97, 0x01, // Origin Type
        0x00 // USER
  };
  Block paramBlock3(paramData3, sizeof(paramData3));
  DefaultParam param3;
  BOOST_REQUIRE_NO_THROW(param3.wireDecode(paramBlock3));

  BOOST_CHECK_EQUAL(param3.getTargetType(), TYPE_CERT);
  BOOST_CHECK_EQUAL(param3.getOriginType(), TYPE_USER);
  BOOST_CHECK_THROW(param3.getOriginName(), tlv::Error);

  DefaultParam param4(TYPE_CERT, TYPE_USER);
  Block paramBlock4 = param4.wireEncode();
  BOOST_CHECK_EQUAL_COLLECTIONS(paramBlock4.wire(),
                                paramBlock4.wire() + paramBlock4.size(),
                                paramBlock3.wire(),
                                paramBlock3.wire() + paramBlock3.size());
}

BOOST_AUTO_TEST_CASE(DefaultParamEndecError)
{
  DefaultParam wrongParam(TYPE_CERT, TYPE_DEFAULT);
  BOOST_CHECK_THROW(wrongParam.wireEncode(), tlv::Error);

  DefaultParam param;

  const uint8_t wrongParamData1[] = {
    0x80, 0x06, // DefaultParam (Wrong)
      0x97, 0x01, // Target Type
        0x03, // CERT
      0x97, 0x01, // Origin Type
        0x00 // USER
  };
  Block wrongParamBlock1(wrongParamData1, sizeof(wrongParamData1));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock1), tlv::Error);

  const uint8_t wrongParamData2[] = {
    0x81, 0x06, // DefaultParam
      0x91, 0x01, // Target Type (Wrong)
        0x03, // CERT
      0x97, 0x01, // Origin Type
        0x00 // USER
  };
  Block wrongParamBlock2(wrongParamData2, sizeof(wrongParamData2));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock2), tlv::Error);

  const uint8_t wrongParamData3[] = {
    0x81, 0x06, // DefaultParam
      0x97, 0x01, // Target Type
        0x03, // CERT
      0x91, 0x01, // Origin Type (Wrong)
        0x00 // USER
  };
  Block wrongParamBlock3(wrongParamData3, sizeof(wrongParamData3));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock3), tlv::Error);

  const uint8_t wrongParamData4[] = {
    0x81, 0x13, // DefaultParam
      0x97, 0x01, // Target Type
        0x03, // CERT
      0x97, 0x01, // Origin Type
        0x02, // KEY
      0x08, 0x0b, // Name "/test/key" (Wrong)
        0x08, 0x04,
          0x74, 0x65, 0x73, 0x74,
        0x08, 0x03,
          0x6b, 0x65, 0x79
  };
  Block wrongParamBlock4(wrongParamData4, sizeof(wrongParamData4));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock4), tlv::Error);
}

BOOST_AUTO_TEST_CASE(ListParamEndec)
{
  const uint8_t paramData1[] = {
    0x82, 0x10, // ListParam
      0x97, 0x01, // Origin Type
        0x02, // KEY
      0x07, 0x0b, // Origin Name "/test/key"
        0x08, 0x04,
          0x74, 0x65, 0x73, 0x74,
        0x08, 0x03,
          0x6b, 0x65, 0x79
  };

  Block paramBlock1(paramData1, sizeof(paramData1));
  ListParam param1;
  BOOST_REQUIRE_NO_THROW(param1.wireDecode(paramBlock1));

  BOOST_CHECK_EQUAL(param1.getOriginType(), TYPE_KEY);
  BOOST_CHECK_EQUAL(param1.getOriginName(), Name("/test/key"));

  ListParam param2(TYPE_KEY, Name("/test/key"));
  Block paramBlock2 = param2.wireEncode();
  BOOST_CHECK_EQUAL_COLLECTIONS(paramBlock2.wire(),
                                paramBlock2.wire() + paramBlock2.size(),
                                paramBlock1.wire(),
                                paramBlock1.wire() + paramBlock1.size());

  const uint8_t paramData3[] = {
    0x82, 0x03, // ListParam
      0x97, 0x01, // Origin Type
        0x00, // USER
  };
  Block paramBlock3(paramData3, sizeof(paramData3));
  ListParam param3;
  BOOST_REQUIRE_NO_THROW(param3.wireDecode(paramBlock3));

  BOOST_CHECK_EQUAL(param3.getOriginType(), TYPE_USER);
  BOOST_CHECK_THROW(param3.getOriginName(), tlv::Error);

  ListParam param4;
  Block paramBlock4 = param4.wireEncode();
  BOOST_CHECK_EQUAL_COLLECTIONS(paramBlock4.wire(),
                                paramBlock4.wire() + paramBlock4.size(),
                                paramBlock3.wire(),
                                paramBlock3.wire() + paramBlock3.size());
}

BOOST_AUTO_TEST_CASE(ListParamEndecError)
{
  ListParam wrongParam(TYPE_DEFAULT, Name("/test/key"));
  BOOST_CHECK_THROW(wrongParam.wireEncode(), tlv::Error);

  ListParam param;

  const uint8_t wrongParamData1[] = {
    0x81, 0x03, // ListParam (Wrong)
      0x97, 0x01, // Origin Type
        0x00, // USER
  };
  Block wrongParamBlock1(wrongParamData1, sizeof(wrongParamData1));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock1), tlv::Error);

  const uint8_t wrongParamData2[] = {
    0x82, 0x03, // DefaultParam
      0x91, 0x01, // Origin Type (Wrong)
        0x00, // USER
  };
  Block wrongParamBlock2(wrongParamData2, sizeof(wrongParamData2));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock2), tlv::Error);

  const uint8_t wrongParamData3[] = {
    0x82, 0x10, // ListParam
      0x97, 0x01, // Origin Type
        0x02, // KEY
      0x08, 0x0b, // Origin Name "/test/key" (Wrong)
        0x08, 0x04,
          0x74, 0x65, 0x73, 0x74,
        0x08, 0x03,
          0x6b, 0x65, 0x79
  };
  Block wrongParamBlock3(wrongParamData3, sizeof(wrongParamData3));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock3), tlv::Error);
}

BOOST_AUTO_TEST_CASE(UpdateParamEndec)
{
  const uint8_t paramData1[] = {
    0x83, 0x0d, // UpdateParam
      0x91, 0x08, // Idenity
        0x07, 0x06, // Name "/test"
          0x08, 0x04,
            0x74, 0x65, 0x73, 0x74,
      0x95, 0x01, // DefaultOpt
        0x07 // DEFAULT_OPT_USER
  };

  Block paramBlock1(paramData1, sizeof(paramData1));
  UpdateParam param1;
  BOOST_REQUIRE_NO_THROW(param1.wireDecode(paramBlock1));

  BOOST_CHECK_EQUAL(param1.getEntityType(), static_cast<uint32_t>(tlv::pib::Identity));
  BOOST_CHECK_EQUAL(param1.getIdentity().getIdentity(), Name("/test"));
  BOOST_CHECK_EQUAL(param1.getDefaultOpt(), DEFAULT_OPT_USER);
  BOOST_CHECK_THROW(param1.getPublicKey(), tlv::Error);
  BOOST_CHECK_THROW(param1.getCertificate(), tlv::Error);
  BOOST_CHECK_THROW(param1.getUser(), tlv::Error);

  UpdateParam param2(Name("/test"), DEFAULT_OPT_USER);
  Block paramBlock2 = param2.wireEncode();
  BOOST_CHECK_EQUAL_COLLECTIONS(paramBlock2.wire(),
                                paramBlock2.wire() + paramBlock2.size(),
                                paramBlock1.wire(),
                                paramBlock1.wire() + paramBlock1.size());

  const uint8_t paramData3[] = {
    0x83, 0x6F, // UpdateParam
      0x92, 0x6A, // PublicKey
        0x07, 0x0b, // Name "/test"
          0x08, 0x04,
            0x74, 0x65, 0x73, 0x74,
          0x08, 0x03,
            0x6b, 0x65, 0x79,
        0x94, 0x5b, // Bytes
          0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
          0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
          0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x35, 0x9a, 0x6a,
          0x90, 0xf2, 0x43, 0x8f, 0xcb, 0xa1, 0x4a, 0x97, 0xdf, 0x3a,
          0x20, 0x9b, 0xbd, 0x26, 0x0c, 0x2e, 0xc1, 0x81, 0xd4, 0x4a,
          0x3f, 0x59, 0x4e, 0xa6, 0xad, 0xec, 0x63, 0x1a, 0xf7, 0x6e,
          0x41, 0x78, 0xea, 0xc2, 0x89, 0xff, 0x79, 0x21, 0xc5, 0x23,
          0xa1, 0x20, 0x1d, 0x99, 0x3c, 0x2f, 0xd2, 0x9f, 0x89, 0x5e,
          0x57, 0x56, 0xd5, 0x6c, 0x93, 0x68, 0x39, 0xc0, 0x8a, 0x49,
          0x56,
      0x95, 0x01, // DefaultOpt
        0x00 // DEFAULT_OPT_NO
  };

  const uint8_t publicKeyData[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x35, 0x9a, 0x6a,
    0x90, 0xf2, 0x43, 0x8f, 0xcb, 0xa1, 0x4a, 0x97, 0xdf, 0x3a,
    0x20, 0x9b, 0xbd, 0x26, 0x0c, 0x2e, 0xc1, 0x81, 0xd4, 0x4a,
    0x3f, 0x59, 0x4e, 0xa6, 0xad, 0xec, 0x63, 0x1a, 0xf7, 0x6e,
    0x41, 0x78, 0xea, 0xc2, 0x89, 0xff, 0x79, 0x21, 0xc5, 0x23,
    0xa1, 0x20, 0x1d, 0x99, 0x3c, 0x2f, 0xd2, 0x9f, 0x89, 0x5e,
    0x57, 0x56, 0xd5, 0x6c, 0x93, 0x68, 0x39, 0xc0, 0x8a, 0x49,
    0x56
  };

  PublicKey key(publicKeyData, sizeof(publicKeyData));

  Block paramBlock3(paramData3, sizeof(paramData3));
  UpdateParam param3;
  BOOST_REQUIRE_NO_THROW(param3.wireDecode(paramBlock3));

  BOOST_CHECK_EQUAL(param3.getEntityType(), static_cast<uint32_t>(tlv::pib::PublicKey));
  BOOST_REQUIRE_NO_THROW(param3.getPublicKey());
  BOOST_CHECK_EQUAL(param3.getPublicKey().getKeyName(), Name("/test/key"));
  BOOST_CHECK_EQUAL(param3.getDefaultOpt(), DEFAULT_OPT_NO);
  BOOST_CHECK_THROW(param3.getIdentity(), tlv::Error);
  BOOST_CHECK_THROW(param3.getCertificate(), tlv::Error);
  BOOST_CHECK_THROW(param3.getUser(), tlv::Error);

  const PublicKey& decodedKey = param3.getPublicKey().getPublicKey();
  BOOST_CHECK_EQUAL_COLLECTIONS(decodedKey.get().buf(),
                                decodedKey.get().buf() + decodedKey.get().size(),
                                publicKeyData,
                                publicKeyData + sizeof(publicKeyData));

  UpdateParam param4(Name("/test/key"), key, DEFAULT_OPT_NO);
  Block paramBlock4 = param4.wireEncode();
  BOOST_CHECK_EQUAL_COLLECTIONS(paramBlock4.wire(),
                                paramBlock4.wire() + paramBlock4.size(),
                                paramBlock3.wire(),
                                paramBlock3.wire() + paramBlock3.size());

  const uint8_t paramData5[] = {
    0x83, 0xfd, 0x01, 0x62,// UpdateParam
      0x93, 0xfd, 0x01, 0x5b, // Certificate
        0x06, 0xfd, 0x01, 0x57, 0x07, 0x31, 0x08, 0x04, 0x74, 0x65, 0x73, 0x74, 0x08, 0x03, 0x4b,
        0x45, 0x59, 0x08, 0x11, 0x6b, 0x73, 0x6b, 0x2d, 0x31, 0x34, 0x30, 0x35, 0x34, 0x34, 0x39,
        0x33, 0x32, 0x39, 0x31, 0x34, 0x35, 0x08, 0x07, 0x49, 0x44, 0x2d, 0x43, 0x45, 0x52, 0x54,
        0x08, 0x08, 0x00, 0x00, 0x01, 0x47, 0x3b, 0x4e, 0xd9, 0xfe, 0x14, 0x03, 0x18, 0x01, 0x02,
        0x15, 0xa4, 0x30, 0x81, 0xa1, 0x30, 0x22, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x34, 0x30, 0x37,
        0x31, 0x35, 0x31, 0x38, 0x33, 0x35, 0x32, 0x39, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x33, 0x34,
        0x30, 0x37, 0x31, 0x30, 0x31, 0x38, 0x33, 0x35, 0x32, 0x39, 0x5a, 0x30, 0x20, 0x30, 0x1e,
        0x06, 0x03, 0x55, 0x04, 0x29, 0x13, 0x17, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x2f, 0x6b, 0x73,
        0x6b, 0x2d, 0x31, 0x34, 0x30, 0x35, 0x34, 0x34, 0x39, 0x33, 0x32, 0x39, 0x31, 0x34, 0x35,
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x1b, 0xe6, 0x38,
        0x96, 0x52, 0x79, 0x15, 0x90, 0xc4, 0x83, 0xe4, 0x5e, 0x2d, 0x15, 0xdb, 0x83, 0xe9, 0xc0,
        0x73, 0x54, 0x61, 0x99, 0xd0, 0x81, 0x76, 0x5b, 0xd1, 0x7c, 0x34, 0x36, 0x63, 0x3f, 0x45,
        0x65, 0x3a, 0x72, 0x88, 0x0b, 0x79, 0x4a, 0x1d, 0x83, 0x37, 0x82, 0xda, 0x97, 0xb8, 0x31,
        0x89, 0x56, 0xa5, 0xc8, 0x36, 0x4d, 0xf8, 0x28, 0x44, 0x0a, 0x70, 0x4c, 0x10, 0xfc, 0x20,
        0xfe, 0x16, 0x2e, 0x1b, 0x01, 0x03, 0x1c, 0x29, 0x07, 0x27, 0x08, 0x04, 0x74, 0x65, 0x73,
        0x74, 0x08, 0x03, 0x4b, 0x45, 0x59, 0x08, 0x11, 0x6b, 0x73, 0x6b, 0x2d, 0x31, 0x34, 0x30,
        0x35, 0x34, 0x34, 0x39, 0x33, 0x32, 0x39, 0x31, 0x34, 0x35, 0x08, 0x07, 0x49, 0x44, 0x2d,
        0x43, 0x45, 0x52, 0x54, 0x17, 0x47, 0x30, 0x45, 0x02, 0x20, 0x0c, 0xe4, 0x02, 0xd3, 0xc5,
        0x46, 0xf4, 0x1f, 0x41, 0x02, 0x27, 0xbb, 0x69, 0xf5, 0x9b, 0x9c, 0x1e, 0x8d, 0x9a, 0xce,
        0x4d, 0xeb, 0x3b, 0x50, 0xbc, 0x60, 0xb4, 0x03, 0x74, 0x08, 0x14, 0xa5, 0x02, 0x21, 0x00,
        0xca, 0x20, 0x0c, 0xe8, 0x25, 0x84, 0x5d, 0xa2, 0x86, 0xea, 0x21, 0x30, 0x6c, 0x9c, 0x28,
        0xeb, 0xc7, 0x16, 0x57, 0x46, 0xf9, 0x89, 0xbb, 0x19, 0x5a, 0xf0, 0xfc, 0xe0, 0xc7, 0x64,
        0xf4, 0x41,
      0x95, 0x01, // DefaultOpt
        0x03 // DEFAULT_OPT_ID

  };
  const uint8_t certData[] = {
    0x06, 0xfd, 0x01, 0x57, 0x07, 0x31, 0x08, 0x04, 0x74, 0x65, 0x73, 0x74, 0x08, 0x03, 0x4b,
    0x45, 0x59, 0x08, 0x11, 0x6b, 0x73, 0x6b, 0x2d, 0x31, 0x34, 0x30, 0x35, 0x34, 0x34, 0x39,
    0x33, 0x32, 0x39, 0x31, 0x34, 0x35, 0x08, 0x07, 0x49, 0x44, 0x2d, 0x43, 0x45, 0x52, 0x54,
    0x08, 0x08, 0x00, 0x00, 0x01, 0x47, 0x3b, 0x4e, 0xd9, 0xfe, 0x14, 0x03, 0x18, 0x01, 0x02,
    0x15, 0xa4, 0x30, 0x81, 0xa1, 0x30, 0x22, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x34, 0x30, 0x37,
    0x31, 0x35, 0x31, 0x38, 0x33, 0x35, 0x32, 0x39, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x33, 0x34,
    0x30, 0x37, 0x31, 0x30, 0x31, 0x38, 0x33, 0x35, 0x32, 0x39, 0x5a, 0x30, 0x20, 0x30, 0x1e,
    0x06, 0x03, 0x55, 0x04, 0x29, 0x13, 0x17, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x2f, 0x6b, 0x73,
    0x6b, 0x2d, 0x31, 0x34, 0x30, 0x35, 0x34, 0x34, 0x39, 0x33, 0x32, 0x39, 0x31, 0x34, 0x35,
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x1b, 0xe6, 0x38,
    0x96, 0x52, 0x79, 0x15, 0x90, 0xc4, 0x83, 0xe4, 0x5e, 0x2d, 0x15, 0xdb, 0x83, 0xe9, 0xc0,
    0x73, 0x54, 0x61, 0x99, 0xd0, 0x81, 0x76, 0x5b, 0xd1, 0x7c, 0x34, 0x36, 0x63, 0x3f, 0x45,
    0x65, 0x3a, 0x72, 0x88, 0x0b, 0x79, 0x4a, 0x1d, 0x83, 0x37, 0x82, 0xda, 0x97, 0xb8, 0x31,
    0x89, 0x56, 0xa5, 0xc8, 0x36, 0x4d, 0xf8, 0x28, 0x44, 0x0a, 0x70, 0x4c, 0x10, 0xfc, 0x20,
    0xfe, 0x16, 0x2e, 0x1b, 0x01, 0x03, 0x1c, 0x29, 0x07, 0x27, 0x08, 0x04, 0x74, 0x65, 0x73,
    0x74, 0x08, 0x03, 0x4b, 0x45, 0x59, 0x08, 0x11, 0x6b, 0x73, 0x6b, 0x2d, 0x31, 0x34, 0x30,
    0x35, 0x34, 0x34, 0x39, 0x33, 0x32, 0x39, 0x31, 0x34, 0x35, 0x08, 0x07, 0x49, 0x44, 0x2d,
    0x43, 0x45, 0x52, 0x54, 0x17, 0x47, 0x30, 0x45, 0x02, 0x20, 0x0c, 0xe4, 0x02, 0xd3, 0xc5,
    0x46, 0xf4, 0x1f, 0x41, 0x02, 0x27, 0xbb, 0x69, 0xf5, 0x9b, 0x9c, 0x1e, 0x8d, 0x9a, 0xce,
    0x4d, 0xeb, 0x3b, 0x50, 0xbc, 0x60, 0xb4, 0x03, 0x74, 0x08, 0x14, 0xa5, 0x02, 0x21, 0x00,
    0xca, 0x20, 0x0c, 0xe8, 0x25, 0x84, 0x5d, 0xa2, 0x86, 0xea, 0x21, 0x30, 0x6c, 0x9c, 0x28,
    0xeb, 0xc7, 0x16, 0x57, 0x46, 0xf9, 0x89, 0xbb, 0x19, 0x5a, 0xf0, 0xfc, 0xe0, 0xc7, 0x64,
    0xf4, 0x41
  };

  Block certBlock(certData, sizeof(certData));
  IdentityCertificate cert;
  cert.wireDecode(certBlock);

  Block paramBlock5(paramData5, sizeof(paramData5));
  UpdateParam param5;
  BOOST_REQUIRE_NO_THROW(param5.wireDecode(paramBlock5));

  BOOST_CHECK_EQUAL(param5.getEntityType(), static_cast<uint32_t>(tlv::pib::Certificate));
  BOOST_REQUIRE_NO_THROW(param5.getCertificate());
  BOOST_CHECK_EQUAL(param5.getDefaultOpt(), DEFAULT_OPT_ID);
  BOOST_CHECK_THROW(param5.getIdentity(), tlv::Error);
  BOOST_CHECK_THROW(param5.getPublicKey(), tlv::Error);
  BOOST_CHECK_THROW(param5.getUser(), tlv::Error);

  const IdentityCertificate& decodedCert = param5.getCertificate().getCertificate();
  BOOST_CHECK_EQUAL_COLLECTIONS(decodedCert.wireEncode().wire(),
                                decodedCert.wireEncode().wire() + decodedCert.wireEncode().size(),
                                certData,
                                certData + sizeof(certData));

  UpdateParam param6(cert, DEFAULT_OPT_ID);
  Block paramBlock6 = param6.wireEncode();
  BOOST_CHECK_EQUAL_COLLECTIONS(paramBlock6.wire(),
                                paramBlock6.wire() + paramBlock6.size(),
                                paramBlock5.wire(),
                                paramBlock5.wire() + paramBlock5.size());


  const uint8_t paramData7[] = {
    0x83, 0xfd, 0x01, 0x62,// UpdateParam
      0x90, 0xfd, 0x01, 0x5b, // User
        0x06, 0xfd, 0x01, 0x57, 0x07, 0x31, 0x08, 0x04, 0x74, 0x65, 0x73, 0x74, 0x08, 0x03, 0x4b,
        0x45, 0x59, 0x08, 0x11, 0x6b, 0x73, 0x6b, 0x2d, 0x31, 0x34, 0x30, 0x35, 0x34, 0x34, 0x39,
        0x33, 0x32, 0x39, 0x31, 0x34, 0x35, 0x08, 0x07, 0x49, 0x44, 0x2d, 0x43, 0x45, 0x52, 0x54,
        0x08, 0x08, 0x00, 0x00, 0x01, 0x47, 0x3b, 0x4e, 0xd9, 0xfe, 0x14, 0x03, 0x18, 0x01, 0x02,
        0x15, 0xa4, 0x30, 0x81, 0xa1, 0x30, 0x22, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x34, 0x30, 0x37,
        0x31, 0x35, 0x31, 0x38, 0x33, 0x35, 0x32, 0x39, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x33, 0x34,
        0x30, 0x37, 0x31, 0x30, 0x31, 0x38, 0x33, 0x35, 0x32, 0x39, 0x5a, 0x30, 0x20, 0x30, 0x1e,
        0x06, 0x03, 0x55, 0x04, 0x29, 0x13, 0x17, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x2f, 0x6b, 0x73,
        0x6b, 0x2d, 0x31, 0x34, 0x30, 0x35, 0x34, 0x34, 0x39, 0x33, 0x32, 0x39, 0x31, 0x34, 0x35,
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x1b, 0xe6, 0x38,
        0x96, 0x52, 0x79, 0x15, 0x90, 0xc4, 0x83, 0xe4, 0x5e, 0x2d, 0x15, 0xdb, 0x83, 0xe9, 0xc0,
        0x73, 0x54, 0x61, 0x99, 0xd0, 0x81, 0x76, 0x5b, 0xd1, 0x7c, 0x34, 0x36, 0x63, 0x3f, 0x45,
        0x65, 0x3a, 0x72, 0x88, 0x0b, 0x79, 0x4a, 0x1d, 0x83, 0x37, 0x82, 0xda, 0x97, 0xb8, 0x31,
        0x89, 0x56, 0xa5, 0xc8, 0x36, 0x4d, 0xf8, 0x28, 0x44, 0x0a, 0x70, 0x4c, 0x10, 0xfc, 0x20,
        0xfe, 0x16, 0x2e, 0x1b, 0x01, 0x03, 0x1c, 0x29, 0x07, 0x27, 0x08, 0x04, 0x74, 0x65, 0x73,
        0x74, 0x08, 0x03, 0x4b, 0x45, 0x59, 0x08, 0x11, 0x6b, 0x73, 0x6b, 0x2d, 0x31, 0x34, 0x30,
        0x35, 0x34, 0x34, 0x39, 0x33, 0x32, 0x39, 0x31, 0x34, 0x35, 0x08, 0x07, 0x49, 0x44, 0x2d,
        0x43, 0x45, 0x52, 0x54, 0x17, 0x47, 0x30, 0x45, 0x02, 0x20, 0x0c, 0xe4, 0x02, 0xd3, 0xc5,
        0x46, 0xf4, 0x1f, 0x41, 0x02, 0x27, 0xbb, 0x69, 0xf5, 0x9b, 0x9c, 0x1e, 0x8d, 0x9a, 0xce,
        0x4d, 0xeb, 0x3b, 0x50, 0xbc, 0x60, 0xb4, 0x03, 0x74, 0x08, 0x14, 0xa5, 0x02, 0x21, 0x00,
        0xca, 0x20, 0x0c, 0xe8, 0x25, 0x84, 0x5d, 0xa2, 0x86, 0xea, 0x21, 0x30, 0x6c, 0x9c, 0x28,
        0xeb, 0xc7, 0x16, 0x57, 0x46, 0xf9, 0x89, 0xbb, 0x19, 0x5a, 0xf0, 0xfc, 0xe0, 0xc7, 0x64,
        0xf4, 0x41,
      0x95, 0x01, // DefaultOpt
        0x00 // DEFAULT_OPT_NO
  };

  Block paramBlock7(paramData7, sizeof(paramData7));
  UpdateParam param7;
  BOOST_REQUIRE_NO_THROW(param7.wireDecode(paramBlock7));

  BOOST_CHECK_EQUAL(param7.getEntityType(), static_cast<uint32_t>(tlv::pib::User));
  BOOST_REQUIRE_NO_THROW(param7.getUser());
  BOOST_CHECK_EQUAL(param7.getDefaultOpt(), DEFAULT_OPT_NO);
  BOOST_CHECK_THROW(param7.getIdentity(), tlv::Error);
  BOOST_CHECK_THROW(param7.getPublicKey(), tlv::Error);
  BOOST_CHECK_THROW(param7.getCertificate(), tlv::Error);

  const IdentityCertificate& decodedCert7 = param7.getUser().getMgmtCert();
  BOOST_CHECK_EQUAL_COLLECTIONS(decodedCert7.wireEncode().wire(),
                                decodedCert7.wireEncode().wire() + decodedCert7.wireEncode().size(),
                                certData,
                                certData + sizeof(certData));

  PibUser pibUser;
  pibUser.setMgmtCert(cert);
  UpdateParam param8(pibUser);
  Block paramBlock8 = param8.wireEncode();
  BOOST_CHECK_EQUAL_COLLECTIONS(paramBlock8.wire(),
                                paramBlock8.wire() + paramBlock8.size(),
                                paramBlock7.wire(),
                                paramBlock7.wire() + paramBlock7.size());

  const uint8_t paramData9[] = {
    0x83, 0xfd, 0x01, 0x6E,// UpdateParam
      0x90, 0xfd, 0x01, 0x67, // User
        0x06, 0xfd, 0x01, 0x57, 0x07, 0x31, 0x08, 0x04, 0x74, 0x65, 0x73, 0x74, 0x08, 0x03, 0x4b,
        0x45, 0x59, 0x08, 0x11, 0x6b, 0x73, 0x6b, 0x2d, 0x31, 0x34, 0x30, 0x35, 0x34, 0x34, 0x39,
        0x33, 0x32, 0x39, 0x31, 0x34, 0x35, 0x08, 0x07, 0x49, 0x44, 0x2d, 0x43, 0x45, 0x52, 0x54,
        0x08, 0x08, 0x00, 0x00, 0x01, 0x47, 0x3b, 0x4e, 0xd9, 0xfe, 0x14, 0x03, 0x18, 0x01, 0x02,
        0x15, 0xa4, 0x30, 0x81, 0xa1, 0x30, 0x22, 0x18, 0x0f, 0x32, 0x30, 0x31, 0x34, 0x30, 0x37,
        0x31, 0x35, 0x31, 0x38, 0x33, 0x35, 0x32, 0x39, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x33, 0x34,
        0x30, 0x37, 0x31, 0x30, 0x31, 0x38, 0x33, 0x35, 0x32, 0x39, 0x5a, 0x30, 0x20, 0x30, 0x1e,
        0x06, 0x03, 0x55, 0x04, 0x29, 0x13, 0x17, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x2f, 0x6b, 0x73,
        0x6b, 0x2d, 0x31, 0x34, 0x30, 0x35, 0x34, 0x34, 0x39, 0x33, 0x32, 0x39, 0x31, 0x34, 0x35,
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x1b, 0xe6, 0x38,
        0x96, 0x52, 0x79, 0x15, 0x90, 0xc4, 0x83, 0xe4, 0x5e, 0x2d, 0x15, 0xdb, 0x83, 0xe9, 0xc0,
        0x73, 0x54, 0x61, 0x99, 0xd0, 0x81, 0x76, 0x5b, 0xd1, 0x7c, 0x34, 0x36, 0x63, 0x3f, 0x45,
        0x65, 0x3a, 0x72, 0x88, 0x0b, 0x79, 0x4a, 0x1d, 0x83, 0x37, 0x82, 0xda, 0x97, 0xb8, 0x31,
        0x89, 0x56, 0xa5, 0xc8, 0x36, 0x4d, 0xf8, 0x28, 0x44, 0x0a, 0x70, 0x4c, 0x10, 0xfc, 0x20,
        0xfe, 0x16, 0x2e, 0x1b, 0x01, 0x03, 0x1c, 0x29, 0x07, 0x27, 0x08, 0x04, 0x74, 0x65, 0x73,
        0x74, 0x08, 0x03, 0x4b, 0x45, 0x59, 0x08, 0x11, 0x6b, 0x73, 0x6b, 0x2d, 0x31, 0x34, 0x30,
        0x35, 0x34, 0x34, 0x39, 0x33, 0x32, 0x39, 0x31, 0x34, 0x35, 0x08, 0x07, 0x49, 0x44, 0x2d,
        0x43, 0x45, 0x52, 0x54, 0x17, 0x47, 0x30, 0x45, 0x02, 0x20, 0x0c, 0xe4, 0x02, 0xd3, 0xc5,
        0x46, 0xf4, 0x1f, 0x41, 0x02, 0x27, 0xbb, 0x69, 0xf5, 0x9b, 0x9c, 0x1e, 0x8d, 0x9a, 0xce,
        0x4d, 0xeb, 0x3b, 0x50, 0xbc, 0x60, 0xb4, 0x03, 0x74, 0x08, 0x14, 0xa5, 0x02, 0x21, 0x00,
        0xca, 0x20, 0x0c, 0xe8, 0x25, 0x84, 0x5d, 0xa2, 0x86, 0xea, 0x21, 0x30, 0x6c, 0x9c, 0x28,
        0xeb, 0xc7, 0x16, 0x57, 0x46, 0xf9, 0x89, 0xbb, 0x19, 0x5a, 0xf0, 0xfc, 0xe0, 0xc7, 0x64,
        0xf4, 0x41,
        0x99, 0x0a, 0x54, 0x70, 0x6d, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, // TpmLocator
      0x95, 0x01, // DefaultOpt
        0x00 // DEFAULT_OPT_NO
  };

  Block paramBlock9(paramData9, sizeof(paramData9));
  UpdateParam param9;
  BOOST_REQUIRE_NO_THROW(param9.wireDecode(paramBlock9));

  BOOST_CHECK_EQUAL(param9.getEntityType(), static_cast<uint32_t>(tlv::pib::User));
  BOOST_REQUIRE_NO_THROW(param9.getUser());
  BOOST_CHECK_EQUAL(param9.getDefaultOpt(), DEFAULT_OPT_NO);
  BOOST_CHECK_THROW(param9.getIdentity(), tlv::Error);
  BOOST_CHECK_THROW(param9.getPublicKey(), tlv::Error);
  BOOST_CHECK_THROW(param9.getCertificate(), tlv::Error);

  const IdentityCertificate& decodedCert9 = param9.getUser().getMgmtCert();
  BOOST_CHECK_EQUAL_COLLECTIONS(decodedCert9.wireEncode().wire(),
                                decodedCert9.wireEncode().wire() + decodedCert9.wireEncode().size(),
                                certData,
                                certData + sizeof(certData));

  BOOST_CHECK_EQUAL(param9.getUser().getTpmLocator(), "TpmLocator");

  PibUser pibUser2;
  pibUser2.setMgmtCert(cert);
  pibUser2.setTpmLocator("TpmLocator");
  UpdateParam param10(pibUser2);
  Block paramBlock10 = param10.wireEncode();
  BOOST_CHECK(paramBlock10 == paramBlock9);
}

BOOST_AUTO_TEST_CASE(UpdateParamEndecError)
{
  UpdateParam wrongParam;
  BOOST_CHECK_THROW(wrongParam.wireEncode(), tlv::Error);

  UpdateParam param;

  const uint8_t wrongParamData1[] = {
    0x82, 0x0d, // UpdateParam (Wrong)
      0x91, 0x08, // Idenity
        0x07, 0x06, // Name "/test"
          0x08, 0x04,
            0x74, 0x65, 0x73, 0x74,
      0x95, 0x01, // DefaultOpt
        0x01 // USER_DEFAULT
  };
  Block wrongParamBlock1(wrongParamData1, sizeof(wrongParamData1));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock1), tlv::Error);

  const uint8_t wrongParamData2[] = {
    0x83, 0x0d, // UpdateParam
      0x91, 0x08, // Idenity
        0x08, 0x06, // Name "/test" (Wrong)
          0x08, 0x04,
            0x74, 0x65, 0x73, 0x74,
      0x95, 0x01, // DefaultOpt
        0x01 // USER_DEFAULT
  };
  Block wrongParamBlock2(wrongParamData2, sizeof(wrongParamData2));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock2), tlv::Error);

  const uint8_t wrongParamData3[] = {
    0x83, 0x0d, // UpdateParam
      0x92, 0x08, // PublicKey
        0x07, 0x06, // Name "/test"
          0x08, 0x04,
            0x74, 0x65, 0x73, 0x74, // Missing Bytes (Wrong)
      0x95, 0x01, // DefaultOpt
        0x01 // USER_DEFAULT
  };
  Block wrongParamBlock3(wrongParamData3, sizeof(wrongParamData3));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock3), tlv::Error);

  const uint8_t wrongParamData4[] = {
    0x83, 0x0d, // UpdateParam
      0x93, 0x08, // Certificate
        0x07, 0x06, // Name "/test" (Wrong)
          0x08, 0x04,
            0x74, 0x65, 0x73, 0x74,
      0x95, 0x01, // DefaultOpt
        0x01 // USER_DEFAULT
  };
  Block wrongParamBlock4(wrongParamData4, sizeof(wrongParamData4));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock4), tlv::Error);
}

BOOST_AUTO_TEST_CASE(DeleteParamEndec)
{
  const uint8_t paramData1[] = {
    0x84, 0x0b, // DeleteParam
      0x97, 0x01, // Type
        0x01, // ID
      0x07, 0x06, // Name "/test"
        0x08, 0x04,
          0x74, 0x65, 0x73, 0x74
  };

  Block paramBlock1(paramData1, sizeof(paramData1));
  DeleteParam param1;
  BOOST_REQUIRE_NO_THROW(param1.wireDecode(paramBlock1));

  BOOST_CHECK_EQUAL(param1.getTargetType(), static_cast<uint32_t>(TYPE_ID));
  BOOST_CHECK_EQUAL(param1.getTargetName(), Name("/test"));

  DeleteParam param2(Name("/test"), TYPE_ID);
  Block paramBlock2 = param2.wireEncode();
  BOOST_CHECK_EQUAL_COLLECTIONS(paramBlock2.wire(),
                                paramBlock2.wire() + paramBlock2.size(),
                                paramBlock1.wire(),
                                paramBlock1.wire() + paramBlock1.size());
}

BOOST_AUTO_TEST_CASE(DeleteParamEndecError)
{
  DeleteParam wrongParam(Name("/test"), pib::TYPE_DEFAULT);
  BOOST_CHECK_THROW(wrongParam.wireEncode(), tlv::Error);

  DeleteParam param;

  const uint8_t wrongParamData1[] = {
    0x83, 0x0b, // DeleteParam (Wrong)
      0x97, 0x01, // Type
        0x01, // ID
      0x07, 0x06, // Name "/test"
        0x08, 0x04,
          0x74, 0x65, 0x73, 0x74
  };
  Block wrongParamBlock1(wrongParamData1, sizeof(wrongParamData1));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock1), tlv::Error);

  const uint8_t wrongParamData2[] = {
    0x84, 0x0b, // DeleteParam
      0x91, 0x01, // Type (Wrong)
        0x01, // ID
      0x07, 0x06, // Name "/test"
        0x08, 0x04,
          0x74, 0x65, 0x73, 0x74
  };
  Block wrongParamBlock2(wrongParamData2, sizeof(wrongParamData2));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock2), tlv::Error);

  const uint8_t wrongParamData3[] = {
    0x84, 0x0b, // DeleteParam
      0x97, 0x01, // Type
        0x01, // ID
      0x08, 0x06, // Name "/test"  (Wrong)
        0x08, 0x04,
          0x74, 0x65, 0x73, 0x74
  };
  Block wrongParamBlock3(wrongParamData3, sizeof(wrongParamData3));
  BOOST_CHECK_THROW(param.wireDecode(wrongParamBlock3), tlv::Error);
}

BOOST_AUTO_TEST_CASE(PibNameListEndec)
{
  const uint8_t wire1[] = {
    0x96, 0x24, // PibNameList
      0x07, 0x0a, // Name "/test/01"
        0x08, 0x04,
          0x74, 0x65, 0x73, 0x74,
        0x08, 0x02,
          0x30, 0x31,
      0x07, 0x0a, // Name "/test/02"
        0x08, 0x04,
          0x74, 0x65, 0x73, 0x74,
        0x08, 0x02,
          0x30, 0x32,
      0x07, 0x0a, // Name "/test/03"
        0x08, 0x04,
          0x74, 0x65, 0x73, 0x74,
        0x08, 0x02,
          0x30, 0x33
  };
  std::vector<Name> nameList;
  nameList.push_back(Name("/test/01"));
  nameList.push_back(Name("/test/02"));
  nameList.push_back(Name("/test/03"));

  Block wireBlock1(wire1, sizeof(wire1));
  PibNameList list1;
  BOOST_REQUIRE_NO_THROW(list1.wireDecode(wireBlock1));
  BOOST_CHECK(nameList == list1.getNameList());

  PibNameList list2(nameList);
  Block wireBlock2 = list2.wireEncode();
  BOOST_CHECK_EQUAL_COLLECTIONS(wireBlock2.wire(),
                                wireBlock2.wire() + wireBlock2.size(),
                                wireBlock1.wire(),
                                wireBlock1.wire() + wireBlock1.size());
}

BOOST_AUTO_TEST_CASE(PibErrorContentEndec)
{
  const uint8_t wire1[] = {
    0x98, 0x05, // PibError
      0xfc, 0x01, // ErrorCode
        0x00,
      0x94, 0x00 // ErrorMsg
  };

  Block wireBlock1(wire1, sizeof(wire1));
  PibError error1;
  BOOST_REQUIRE_NO_THROW(error1.wireDecode(wireBlock1));
  BOOST_CHECK_EQUAL(error1.getErrorCode(), ERR_SUCCESS);
  BOOST_CHECK_EQUAL(error1.getErrorMsg(), "");

  PibError error2(ERR_SUCCESS);
  Block wireBlock2 = error2.wireEncode();
  BOOST_CHECK_EQUAL_COLLECTIONS(wireBlock2.wire(),
                                wireBlock2.wire() + wireBlock2.size(),
                                wireBlock1.wire(),
                                wireBlock1.wire() + wireBlock1.size());

  const uint8_t wire3[] = {
    0x98, 0x0a, // PibError
      0xfc, 0x01, // ErrorCode
        0x01, // ERR_INCOMPLETE_COMMAND
      0x94, 0x05, // ErrorMsg
        0x65, 0x72, 0x72, 0x6f, 0x72 // "error"
  };

  Block wireBlock3(wire3, sizeof(wire3));
  PibError error3;
  BOOST_REQUIRE_NO_THROW(error3.wireDecode(wireBlock3));
  BOOST_CHECK_EQUAL(error3.getErrorCode(), ERR_INCOMPLETE_COMMAND);
  BOOST_CHECK_EQUAL(error3.getErrorMsg(), "error");

  PibError error4(ERR_INCOMPLETE_COMMAND, "error");
  Block wireBlock4 = error4.wireEncode();
  BOOST_CHECK_EQUAL_COLLECTIONS(wireBlock4.wire(),
                                wireBlock4.wire() + wireBlock4.size(),
                                wireBlock3.wire(),
                                wireBlock3.wire() + wireBlock3.size());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace pib
} // namespace ndn
