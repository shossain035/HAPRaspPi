/*
 *  Copyright (c) 2008 Apple Inc. All Rights Reserved.
 *
 *  @APPLE_LICENSE_HEADER_START@
 *
 *  This file contains Original Code and/or Modifications of Original Code
 *  as defined in and that are subject to the Apple Public Source License
 *  Version 2.0 (the 'License'). You may not use this file except in
 *  compliance with the License. Please obtain a copy of the License at
 *  http://www.opensource.apple.com/apsl/ and read it before using this
 *  file.
 *
 *  The Original Code and all software distributed under the License are
 *  distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 *  EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 *  INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 *  Please see the License for the specific language governing rights and
 *  limitations under the License.
 *
 *  @APPLE_LICENSE_HEADER_END@
 */

#ifndef BYTE_STRING
#define BYTE_STRING
#include <vector>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fstream>

/** Utility definition and additional operators to make working with
 * sequences of bytes more easy and less error/leak-prone
 */
typedef std::vector<uint8_t> byte_string;

inline bool operator==(const byte_string &l, const byte_string::value_type &value) {
	return l.size() == 1 && l.at(0) == value;
}

inline byte_string &operator+=(byte_string &l, const byte_string::value_type &value) {
	l.push_back(value);
	return l;
}
inline byte_string &operator+=(byte_string &l, const char &value) {
	l.push_back(value);
	return l;
}

/* RHS must be null-terminated */
inline byte_string &operator+=(byte_string &l, const char* value) {
	l.insert(l.end(), value, value + strlen(value));
	return l;
}

inline byte_string &operator+=(byte_string &l, const byte_string &r) {
	l.insert(l.end(), r.begin(), r.end());
	return l;
}

/* RHS must be null-terminated */
inline bool operator==(const byte_string& l, const byte_string::value_type* r) {
	byte_string::size_type lSize = l.size();
	byte_string::size_type rSize = strlen((const char*)r);
	if(lSize != rSize)
		return false;
	return equal(l.begin(), l.end(), r);
}

inline bool operator!=(const byte_string& l, const byte_string::value_type* r) {
	return !(l == r);
}

inline unsigned char *malloc_copy(const byte_string &l) {
	unsigned char *output = (unsigned char*)malloc(l.size());
	if(!output)
		return NULL;
	memcpy(output, &l[0], l.size());
	return output;
}

inline void printString(const byte_string &data, const char* tag) {
	printf("%s:\n", tag);
	printf("length: %d\n", data.size());

	for (uint8_t byte : data) {
		printf("%02hhx ", byte);
	}
	printf("\n*******************************\n");
}

inline void writeToFile(std::ofstream& outputFile, const byte_string& data) {
	size_t size = data.size();
	
	outputFile.write(reinterpret_cast<const char *>(&size), sizeof(size));
	outputFile.write(reinterpret_cast<const char *>(data.data()), size);
}

inline void readFromFile(std::ifstream& inputFile, byte_string& data) {
	size_t size;
	
	inputFile.read(reinterpret_cast<char *>(&size), sizeof(size));
	data.resize(size);

	inputFile.read(reinterpret_cast<char *>(data.data()), size);
}

#endif
