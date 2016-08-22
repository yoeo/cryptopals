#!/usr/bin/env ruby

require 'benchmark'

MAX_KEY_SIZE = 40
N = 1_000

TEXTS = "
This last set of conditions gives more weight to the smaller of the top
two values in the list of probable key sizes, but there's no guarantee
that the smaller value is more likely to be the correct key size.
However, the next step after attempting to calculate the correct key
size is to break the encryption via brute force and it's going to be
less expensive to try smaller keys than larger ones, so favoring the
smaller key size when you're less certain as to the correctness of
either key seems like the right thing to do.
|
On Tuesday, veteran astronauts Eric Boe and Sunita Williams used
touch-screen simulators to practice docking Boeing Co.'s CST-100
Starliner spacecraft with the space station during a training session
near Lambert-St. Louis International Airport. The simulator, called the
Crew Part-Task Trainer, helps prepare astronauts and flight controllers
for missions, flight conditions and situations including the rendezvous
and docking with the space station.".tr('\n', '').split('|').freeze

# Helpers

def hamming_weight(value)
  value.to_s(2).chars.grep(/1/).length
end

def hamming_distance(values_a, values_b)
  values_a.each_with_index.map do |e, i|
    hamming_weight(e ^ values_b[i].ord)
  end.reduce(&:+)
end

def repeating_xor(values, values_key)
  values.each_with_index.map { |e, i| e ^ values_key[i % values_key.length] }
end

# Sort methods

def zero_sort(values, range: 1..MAX_KEY_SIZE)
  range.map do |e|
    [hamming_distance(values[0...e], values[e...2 * e]) / e.to_f, e]
  end.sort
end

def loop_sort(values, range: 1..MAX_KEY_SIZE)
  range.map do |key_size|
    first, *chunks = values.each_slice(key_size).to_a[0..-2]
    distance = chunks.map do |chunk|
      hamming_distance(first, chunk) / key_size.to_f
    end.reduce(:+) / chunks.length
    [distance, key_size]
  end.sort
end

def rand_sort(values, range: 1..MAX_KEY_SIZE)
  sample_size = 20
  range.map do |key_size|
    chunks = values.each_slice(key_size).to_a[0..-2]
    distance = Array.new(sample_size) do
      hamming_distance(*chunks.sample(2)) / key_size.to_f
    end.reduce(:+) / sample_size
    [distance, key_size]
  end.sort
end

def next_sort(values, range: 1..MAX_KEY_SIZE)
  range.map do |key_size|
    chunk_slices = values.each_slice(key_size).each_slice(2).to_a[0..-2]
    distance = chunk_slices.map do |chunk_a, chunk_b|
      hamming_distance(chunk_a, chunk_b) / key_size.to_f
    end.reduce(:+) / chunk_slices.length
    [distance, key_size]
  end.sort
end

def divergence(sorted_sizes, key_size)
  sorted_sizes.map { |e| e[1] }.index(key_size)
end

Benchmark.bm(40) do |x|
  sort_methods = [:zero_sort, :loop_sort, :rand_sort, :next_sort].freeze
  results = {}

  sort_methods.each do |sort_name|
    sort_proc = Object.method(sort_name)

    x.report(sort_name) do
      results[sort_name] = (1..N).map do
        key_bytes = Array.new(rand(1..MAX_KEY_SIZE)) { rand(0..255) }
        encrypted = repeating_xor(TEXTS.sample.bytes, key_bytes)
        divergence(sort_proc.call(encrypted), key_bytes.length)
      end
    end
  end

  puts
  results.each_pair do |sort_name, result|
    score = result.reduce(:+) / result.length.to_f
    puts " * #{sort_name} divergence -> #{score}  #{result.min}..#{result.max}"
  end
end
