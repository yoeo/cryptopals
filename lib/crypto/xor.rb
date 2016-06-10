# Cryptanalysis helper: XOR based encryption
module Crypto
  module_function

  def xor(*sample)
    raise 'not same length' unless sample.map(&:length).uniq.length == 1
    first = sample.first
    Array.new(first.length) { |i| sample.map { |bytes| bytes[i] }.reduce(:^) }
  end

  def gxor(*sample)
    length = sample.map(&:length).max
    xor(*sample.map { |bytes| bytes.cycle.first(length) })
  end

  def score(bytes)
    to_text(bytes).chars.grep(/[ A-Za-z]/).length
  end

  def transpose(sample)
    size = sample.map(&:length).max
    Array.new(size) { |i| sample.map { |e| e[i] }.reject(&:nil?) }
  end

  def break_xor(bytes)
    (0..255).map do |e|
      decrypted = bytes.map { |x| x ^ e }
      [score(decrypted), e, decrypted]
    end.max
  end

  def break_repeating_xor(bytes, size)
    # transposed = bytes.each_slice(size).to_a[0..-2].transpose
    transposed = transpose(bytes.each_slice(size).to_a)
    gxor(bytes, transposed.map { |e| break_xor(e)[1] })
  end

  def break_one_time_pad(sample)
    size = sample.map(&:length).min
    plain = break_repeating_xor(sample.map { |e| e[0...size] }.reduce(:+), size)
    plain.each_slice(size)
  end
end
