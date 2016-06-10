require 'base64'

require_relative 'crypto'

# Set of basic crypto tests
# see http://cryptopals.com/sets/1/
module Basics
  extend Crypto

  module_function # all functions are accessible everywhere

  # 1. Convert hexadecimal strings to base 64

  def to_values(hex_text)
    hex_text.chars.each_slice(2).map { |e| e.reduce(&:+).to_i 16 }
  end

  def to_triplets(values)
    values.each_slice(3).map { |x| x.reduce { |a, e| a << 8 | e } }
  end

  def to_base64(triplet)
    base64 = ('A'..'Z').to_a + ('a'..'z').to_a + ('0'..'9').to_a + ['+', '/']
    (0..3).to_a.reverse.map { |e| base64[triplet >> (6 * e) & 0b111111] }
  end

  def fill_missing(base64_text, gap)
    return base64_text if gap <= 0
    base64_text[0...-gap] + '=' * gap
  end

  def hex_to_base64(hex_text)
    values = to_values hex_text
    gap = (3 - values.length % 3) % 3

    fill_missing(to_triplets(values + Array.new(gap, 0)).map do |triplet|
      to_base64(triplet)
    end.join, gap)
  end

  # 2. XOR on hexadecimal strings

  def xor_hex_values(hex_text_a, hex_text_b)
    to_hex(xor(to_values(hex_text_a), to_values(hex_text_b)))
  end

  # 3. Byte XOR

  def byte_xor(hex_text)
    to_text(break_xor(to_values(hex_text))[-1])
  end

  # 4. Detect XOR line

  def detect_byte_xor(filename)
    to_text(File.open(filename) do |f|
      f.map { |e| break_xor to_values e }.max
    end[-1])
  end

  # 5.Implement repeating-key XOR

  def xor_encrypt(text, key)
    to_hex gxor(text.bytes, key.bytes)
  end

  # 6. Break repeating-key XOR

  def hamming_weight(value)
    value.to_s(2).chars.grep(/1/).length
  end

  def hamming_distance(values_a, values_b)
    values_a.each_with_index.map do |e, i|
      hamming_weight(e ^ values_b[i].ord)
    end.reduce(&:+)
  end

  def sorted_key_sizes(values, range:1..40)
    range.map do |e|
      [hamming_distance(values[0...e], values[e...2 * e]) / e.to_f, e]
    end.sort
  end

  def unknown_size_xor_crack(values)
    sample = sorted_key_sizes(values)
    sample[0..sample.length / 2].map do |e|
      cracked = break_repeating_xor(values, e[1])
      [score(cracked), cracked]
    end.max
  end

  def repeating_xor_crack(filename)
    to_text(
      unknown_size_xor_crack(Base64.decode64(File.read(filename)).bytes)[1])
  end

  # 7. Decrypt AES in ECB mode with the key

  def decrypt_aes_ecb_file(filename, key_text)
    aes_decrypt(:ECB, Base64.decode64(File.read(filename)), key_text)
  end

  # 8. Detect AES-ECB encryped data

  def detect_aes_ecb(filename)
    File.read(filename).split("\n").each_with_index do |line, i|
      return i if ecb_mode? to_values(line).each_slice(16).to_a
    end
  end
end
