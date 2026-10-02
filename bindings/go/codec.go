// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Marek Cingel

package opentlv

import "github.com/marekcingel/OpenTLV/bindings/go/internal/capi"

// CodecError is a value-conversion status, distinct from TLV framing statuses.
// Native value codecs supply no structured diagnostics. It supports errors.Is.
type CodecError int

const (
	// ErrCodecNullArg identifies a missing required native argument.
	ErrCodecNullArg CodecError = 1
	// ErrCodecBufferTooShort identifies insufficient representation/output capacity.
	ErrCodecBufferTooShort CodecError = 2
	// ErrCodecInvalidValue identifies invalid configuration or value bytes.
	ErrCodecInvalidValue CodecError = 3
	// ErrCodecUnsupported identifies an unsupported direction or codec.
	ErrCodecUnsupported CodecError = 4
	// ErrCodecInvalidStructure identifies invalid framing/schema in structure conversion.
	ErrCodecInvalidStructure CodecError = 5
)

// Error returns the canonical C codec status description.
func (e CodecError) Error() string { return capi.CodecMessage(int(e)) }

// Codec is an immutable typed facade over a C value codec. Its zero value is
// unsupported. It is safe for concurrent use with independent input storage.
// Decode returns owned representations; Encode validates and measures in C.
type Codec[T any] struct {
	config capi.CodecConfig
	from   func(uint64, int64, []byte) T
	to     func(T) (uint64, int64, []byte)
}

// Decode interprets only Value bytes, without selecting a codec by tag.
func (c Codec[T]) Decode(data []byte) (T, error) {
	var zero T
	if c.from == nil {
		return zero, ErrCodecUnsupported
	}
	n, s, b, code := c.config.Decode(data)
	if code != 0 {
		return zero, CodecError(code)
	}
	return c.from(n, s, b), nil
}

// Encode returns an independent encoded Value, or the native conversion error.
func (c Codec[T]) Encode(value T) ([]byte, error) {
	if c.to == nil {
		return nil, ErrCodecUnsupported
	}
	n, s, b := c.to(value)
	result, code := c.config.Encode(n, s, b)
	if code != 0 {
		return nil, CodecError(code)
	}
	return result, nil
}
func unsignedCodec[T ~uint8 | ~uint16 | ~uint32 | ~uint64](config capi.CodecConfig) Codec[T] {
	return Codec[T]{config, func(n uint64, _ int64, _ []byte) T { return T(n) }, func(v T) (uint64, int64, []byte) { return uint64(v), 0, nil }}
}

// Uint8Codec converts exactly one byte.
func Uint8Codec() Codec[uint8] { return unsignedCodec[uint8](capi.CodecConfig{Kind: 1}) }

// Uint16BECodec converts exactly two big-endian bytes.
func Uint16BECodec() Codec[uint16] { return unsignedCodec[uint16](capi.CodecConfig{Kind: 2}) }

// Uint32BECodec converts exactly four big-endian bytes.
func Uint32BECodec() Codec[uint32] { return unsignedCodec[uint32](capi.CodecConfig{Kind: 3}) }

// Uint16LECodec converts exactly two little-endian bytes.
func Uint16LECodec() Codec[uint16] { return unsignedCodec[uint16](capi.CodecConfig{Kind: 4}) }

// Uint32LECodec converts exactly four little-endian bytes.
func Uint32LECodec() Codec[uint32] { return unsignedCodec[uint32](capi.CodecConfig{Kind: 5}) }

// Int64Codec converts minimal big-endian two's-complement bytes.
func Int64Codec() Codec[int64] {
	return Codec[int64]{capi.CodecConfig{Kind: 6}, func(_ uint64, s int64, _ []byte) int64 { return s }, func(v int64) (uint64, int64, []byte) { return 0, v, nil }}
}

// NumberEncoding selects a generic unsigned representation.
type NumberEncoding int

const (
	// NumberBE selects binary big endian.
	NumberBE NumberEncoding = iota
	// NumberLE selects binary little endian.
	NumberLE
	// NumberBCD selects packed decimal with leading zero padding.
	NumberBCD
)

// NumberConfig selects width (zero means minimal) and BCD precision (1..18).
// Binary configurations require Digits zero. C validates configuration on use.
type NumberConfig struct {
	Encoding      NumberEncoding
	Width, Digits int
}

// NumberCodec converts configured uint64 values through the C number codec.
func NumberCodec(c NumberConfig) Codec[uint64] {
	return unsignedCodec[uint64](capi.CodecConfig{Kind: 7, Encoding: int(c.Encoding), Width: c.Width, Digits: c.Digits})
}

// BytesCodec copies arbitrary bytes without semantic interpretation.
func BytesCodec() Codec[[]byte] {
	return Codec[[]byte]{capi.CodecConfig{Kind: 8}, func(_ uint64, _ int64, b []byte) []byte { return b }, func(v []byte) (uint64, int64, []byte) { return 0, 0, v }}
}

// TextAlphabet specifies accepted ASCII characters.
type TextAlphabet int

const (
	// ASCIIPrintable accepts 0x20..0x7E including spaces.
	ASCIIPrintable TextAlphabet = iota
	// ASCIIAlnum accepts only ASCII letters and decimal digits.
	ASCIIAlnum
)

// TextConfig selects a repertoire, optional fixed width and trailing zero padding.
// C validates configuration and rejects embedded zeros.
type TextConfig struct {
	Alphabet    TextAlphabet
	Width       int
	ZeroPadding bool
}

func stringCodec(c capi.CodecConfig) Codec[string] {
	return Codec[string]{c, func(_ uint64, _ int64, b []byte) string { return string(b) }, func(v string) (uint64, int64, []byte) { return 0, 0, []byte(v) }}
}

// TextCodec converts configured ASCII text through the C text codec.
func TextCodec(c TextConfig) Codec[string] {
	return stringCodec(capi.CodecConfig{Kind: 9, Encoding: int(c.Alphabet), Width: c.Width, Padding: c.ZeroPadding})
}

// DigitsCodec converts packed decimal digit strings, retaining leading zeros.
// Width zero selects minimal encoding; positive widths use trailing F padding.
func DigitsCodec(width int) Codec[string] {
	return stringCodec(capi.CodecConfig{Kind: 10, Width: width})
}

// IPv4Codec converts an address in network octet order without address policy.
func IPv4Codec() Codec[[4]byte] {
	return Codec[[4]byte]{capi.CodecConfig{Kind: 11}, func(_ uint64, _ int64, b []byte) [4]byte { return [4]byte(b) }, func(v [4]byte) (uint64, int64, []byte) { return 0, 0, v[:] }}
}

// IPv4ListCodec converts address lists, preserving order and duplicates.
func IPv4ListCodec() Codec[[][4]byte] {
	return Codec[[][4]byte]{capi.CodecConfig{Kind: 12}, func(_ uint64, _ int64, b []byte) [][4]byte {
		out := make([][4]byte, len(b)/4)
		for i := range out {
			copy(out[i][:], b[i*4:i*4+4])
		}
		return out
	}, func(v [][4]byte) (uint64, int64, []byte) {
		b := make([]byte, 0, len(v)*4)
		for _, ip := range v {
			b = append(b, ip[:]...)
		}
		return 0, 0, b
	}}
}
