#include "tlv/reader.h"
#include "tlv/writer.h"

#include <benchmark/benchmark.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

std::vector<uint8_t> encode_stream(std::size_t value_size,
                                   std::size_t entry_count) {
  std::vector<uint8_t> value(value_size, 0x5a);
  const std::size_t length_size = value_size < 0x80 ? 1 :
                                  value_size <= 0xff ? 2 : 3;
  std::vector<uint8_t> encoded(entry_count * (1 + length_size + value_size));
  tlv_writer_t writer;
  if (tlv_writer_init(&writer, encoded.data(), encoded.size()) != TLV_OK) {
    return std::vector<uint8_t>();
  }
  for (std::size_t i = 0; i < entry_count; ++i) {
    if (tlv_writer_write(&writer, static_cast<tlv_tag_t>(i), value.data(),
                         value.size()) != TLV_OK) {
      return std::vector<uint8_t>();
    }
  }
  return encoded;
}

void parse_entries(benchmark::State& state) {
  const std::size_t value_size = static_cast<std::size_t>(state.range(0));
  const std::vector<uint8_t> encoded = encode_stream(value_size, 1);
  if (encoded.empty()) {
    state.SkipWithError("failed to prepare encoded TLV entry");
    return;
  }

  for (auto _ : state) {
    tlv_reader_t reader;
    tlv_entry_t entry;
    benchmark::DoNotOptimize(tlv_reader_init(&reader, encoded.data(),
                                              encoded.size()));
    benchmark::DoNotOptimize(tlv_reader_next(&reader, &entry));
    benchmark::DoNotOptimize(entry.value.data);
    benchmark::DoNotOptimize(entry.value.length);
  }
  state.SetBytesProcessed(state.iterations() *
                          static_cast<int64_t>(encoded.size()));
}

void encode_entries(benchmark::State& state) {
  const std::size_t value_size = static_cast<std::size_t>(state.range(0));
  const std::vector<uint8_t> value(value_size, 0x5a);
  std::vector<uint8_t> output(value_size + 4);

  for (auto _ : state) {
    tlv_writer_t writer;
    benchmark::DoNotOptimize(tlv_writer_init(&writer, output.data(),
                                              output.size()));
    benchmark::DoNotOptimize(tlv_writer_write(&writer, 0x42, value.data(),
                                               value.size()));
    benchmark::ClobberMemory();
  }
  state.SetBytesProcessed(state.iterations() *
                          static_cast<int64_t>(value.size()));
}

void parse_stream(benchmark::State& state) {
  const std::size_t entry_count = static_cast<std::size_t>(state.range(0));
  const std::vector<uint8_t> encoded = encode_stream(16, entry_count);
  if (encoded.empty()) {
    state.SkipWithError("failed to prepare encoded TLV stream");
    return;
  }

  for (auto _ : state) {
    tlv_reader_t reader;
    tlv_entry_t entry;
    benchmark::DoNotOptimize(tlv_reader_init(&reader, encoded.data(),
                                              encoded.size()));
    while (!tlv_reader_at_end(&reader)) {
      benchmark::DoNotOptimize(tlv_reader_next(&reader, &entry));
      benchmark::DoNotOptimize(entry.value.data);
    }
  }
  state.SetItemsProcessed(state.iterations() *
                          static_cast<int64_t>(entry_count));
  state.SetBytesProcessed(state.iterations() *
                          static_cast<int64_t>(encoded.size()));
}

BENCHMARK(parse_entries)->Arg(16)->Arg(127)->Arg(128)->Arg(255)->Arg(256)->Arg(4096);
BENCHMARK(encode_entries)->Arg(16)->Arg(127)->Arg(128)->Arg(255)->Arg(256)->Arg(4096);
BENCHMARK(parse_stream)->Arg(16)->Arg(256)->Arg(4096);

}  // namespace
