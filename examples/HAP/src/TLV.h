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

#ifndef TLV_H
#define TLV_H

#include <memory>

#include <stdexcept>

#include <sstream>
#include <vector>

#ifndef NOCOPY
#define NOCOPY(Type)    private: Type(const Type &); void operator = (const Type &);
#endif

#include "byte_string.h"

class TLV;
typedef std::shared_ptr<TLV> TLV_ref;
typedef std::vector<TLV_ref> TLVList;

/** Utility class to simplify TLV parsing and encoding
 *  Condition of proper behavior (assume sizeof(size_t) => ptr size):
 *  32-bit: Total data < 4GB
 *  64-bit: Total data < 4GB * 4GB
 */
class TLV {
	NOCOPY(TLV);
public:
	TLV() throw();
	TLV(uint8_t tag) throw();
	TLV(const byte_string &tag) throw();
	TLV(uint8_t tag, const byte_string &value) throw();
	TLV(const byte_string &tag, const byte_string &value) throw();
	TLV(const byte_string &tag, const TLVList &tlv) throw();
	TLV(uint8_t tag, const TLVList &tlv) throw();

	/* Parses a byte_string as a TLV value - ignores trailing bytes
	 * Throws an error if the encoding is invalid
	 */
	static TLV_ref parse(const byte_string &data) throw(std::runtime_error);

	/* Parses an entire sequence of bytes as a TLV value
	 * - ignores trailing bytes, iter points to byte after TLV
	 * Can accept forward iterators to bytes or pointers to bytes for the range
	 * Ex: byte_string::iterator, unsigned char *
	 * Throws an error if the encoding is invalid
	 */
	template<typename ForwardIterator>
	static TLV_ref parse(ForwardIterator &iter, const ForwardIterator &end) throw(std::runtime_error) {
		byte_string tag;
		uint8_t ch;
		if (iter >= end) throw std::runtime_error("Invalid TLV-encoding");
		/* Read the first byte as the tag */
		ch = *iter++;
		tag += ch;
		if (iter >= end) throw std::runtime_error("Invalid TLV-encoding");
		/* If the tag is flagged as a multibyte tag */
		if ((ch & 0x1F) == 0x1F) { /* Multibyte tag */
			do {
				ch = *iter++;
				tag += ch;
				if (iter >= end) throw std::runtime_error("Invalid TLV-encoding");
				/* Read more until there are no more bytes w/o the high-bit set */
			} while ((ch & 0x80) != 0);
		}
		/* Parse the length of the contained value */
		size_t length = parseLength(iter, end);
		ForwardIterator begin = iter;
		iter += length;
		/* The iterator is permitted to be at the very and at this point */
		if (iter > end) throw std::runtime_error("Invalid TLV-encoding");
		/* Return a new TLV with the calculated tag and value */
		return TLV_ref(new TLV(tag, byte_string(begin, iter)));
	}

	/* Parses an entire sequence of bytes as a sequence of TLV values, appending them to tlv
	* Can accept forward iterators to bytes or pointers to bytes for the range
	* Ex: byte_string::iterator, unsigned char *
	* Throws an error if the encoding is invalid
	*/
	template<typename ForwardIterator>
	static void parseSequence(ForwardIterator &iter, const ForwardIterator &end, TLVList &tlv) throw(std::runtime_error) {
		/* While there is still data inbetween the iterators */
		while (iter < end) {
			/* parse TLV structures and append them to the list */
			TLV_ref ref = TLV::parse(iter, end);
			tlv.push_back(ref);
		}
	}

	/* Obtains the tag of this TLV */
	const byte_string &getTag() const throw() { return tag; }

	/* Encodes this TLV into a new byte_string */
	byte_string encode() const throw();
	/* Encodes this TLV, appending the data to 'out' */
	void encode(byte_string &out) const throw();
	/* Decodes the value of this TLV as a sequence of TLVs */
	const TLVList &getInnerValues() const throw(std::runtime_error);
	/* Obtains the value of this TLV */
	const byte_string &getValue() const throw();

	/* Calculates the length of this TLV */
	size_t length() const throw();

private:
	byte_string tag;
	/* cached/assigned value as a string */
	mutable std::auto_ptr<byte_string> value;
	/* cached/assigned value as a TLV sequence */
	mutable std::auto_ptr<TLVList> innerValues;

	/* Parses the ber-encoded length from a sequence of bytes
	 * Can accept forward iterators to bytes or pointers to bytes for the range
	 * Ex: byte_string::iterator, unsigned char *
	 * Throws an error if the encoding is invalid
	 */
	template<typename ForwardIterator>
	static size_t parseLength(ForwardIterator &iter, const ForwardIterator &end) throw(std::runtime_error) {
		// Parse a BER length field. Returns the value of the length
		uint8_t ch = *iter++;
		if (!(ch & 0x80))	// single byte
			return static_cast<uint32_t>(ch);
		size_t result = 0;
		uint8_t byteLen = ch & 0x7F;
		for (; byteLen > 0; byteLen--) {
			if (iter == end)
				throw std::runtime_error("Invalid BER-encoded length");
			ch = *iter++;
			result = (result << 8) | static_cast<uint8_t>(ch);
		}
		return result;
	}

	/* ber-encodes an integer and writes it's output to 'out' */
	static void encodeLength(size_t value, byte_string &out) throw();
public:
	/* Obtains the length of a ber-encoded integer that would contain the value */
	static size_t encodedLength(size_t value) throw();
private:
	/* Encodes a sequence of TLVs, writing the to 'out' */
	static void encodeSequence(const TLVList &tlv, byte_string &out) throw();

	/* Calculates the total length of the value */
	size_t valueLength() const throw();
};

class TagPredicate {
public:
	TagPredicate(uint8_t tag) throw()
	:tag(1, tag) {
	}
	TagPredicate(const byte_string &tag) throw()
	:tag(tag) {
	}
	bool operator() (const TLV_ref &tlv) throw() {
		return this->tag == tlv->getTag();
	}
private:
	byte_string tag;
};



#endif
