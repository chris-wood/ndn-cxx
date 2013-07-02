/* 
 * Author: Jeff Thompson
 *
 * BSD license, See the LICENSE file for more information.
 */

#include <stdexcept>
#include "../c/encoding/BinaryXMLName.h"
#include "../Name.hpp"
#include "BinaryXMLEncoder.hpp"
#include "BinaryXMLWireFormat.hpp"

using namespace std;

namespace ndn {

BinaryXMLWireFormat BinaryXMLWireFormat::instance_;

void BinaryXMLWireFormat::encodeName(Name &name, vector<unsigned char> &output) 
{
  struct ndn_Name nameStruct;
  struct ndn_NameComponent components[100];
  ndn_Name_init(&nameStruct, components, sizeof(components) / sizeof(components[0]));
  name.get(nameStruct);

  BinaryXMLEncoder encoder;
  ndn_encodeBinaryXMLName(&nameStruct, encoder.getEncoder());
          
  output = vector<unsigned char>(encoder.getEncoder()->output.array, encoder.getEncoder()->output.array + encoder.getEncoder()->offset);
}

void BinaryXMLWireFormat::decodeName(Name &name, const unsigned char *input, unsigned int inputLength)
{
  struct ndn_NameComponent components[100];
  struct ndn_Name nameStruct;
  ndn_Name_init(&nameStruct, components, sizeof(components) / sizeof(components[0]));
    
  char *error;
  if (error = ndn_decodeBinaryXMLName(&nameStruct, (unsigned char *)input, inputLength))
    throw std::runtime_error(error);

  name.set(nameStruct);
}

}