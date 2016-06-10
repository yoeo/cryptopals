#!/usr/bin/env ruby

require 'benchmark'

TEXT =
  'Report? There are statistics. Sequential experiments like: f(x) = x^y'.freeze
N = 1_000

# Score methods

FREQUENCIES = {
  'a' => 0.08167, 'b' => 0.01492, 'c' => 0.02782, 'd' => 0.04253,
  'e' => 0.12702, 'f' => 0.02228, 'g' => 0.02015, 'h' => 0.06094,
  'i' => 0.06966, 'j' => 0.00153, 'k' => 0.00772, 'l' => 0.04025,
  'm' => 0.02406, 'n' => 0.06749, 'o' => 0.07507, 'p' => 0.01929,
  'q' => 0.00095, 'r' => 0.05987, 's' => 0.06327, 't' => 0.09056,
  'u' => 0.02758, 'v' => 0.00978, 'w' => 0.02361, 'x' => 0.00150,
  'y' => 0.01974, 'z' => 0.00074
}.freeze

def get_freq(chars)
  chars.uniq.each_with_object({}) do |e, h|
    h[e] = chars.count(e) / chars.length.to_f
  end
end

def sort_freq(frequencies)
  frequencies.sort { |a, b| a[1] <=> b[1] }
end

def match_freq(a, b, position)
  chunk = 6
  a.send(position, chunk).select { |e| b.send(position, chunk).index(e) }.length
end

def sorted_frequency_score(text)
  useful_chars = text.downcase.chars.grep(/[a-z]/)
  return 0 if useful_chars.empty?

  real_freq = sort_freq(FREQUENCIES).map { |e| e[0] }
  freq = sort_freq(get_freq(useful_chars)).map { |e| e[0] }
  match_freq(freq, real_freq, :first) + match_freq(freq, real_freq, :last)
end

def letter_space_score(text)
  text.chars.grep(/[ A-Za-z]/).length
end

def add_letter_and_fequency_score(text)
  letter_space_score(text) + sorted_frequency_score(text)
end

# Scrambling methods

def bit_shift(text)
  c = Random.srand % 256
  (0..8).map do |size|
    text.bytes.map { |e| (e ^ (c & ((1 << size) - 1))).chr }.join
  end
end

def rand_shift(text)
  c = Random.srand % 256
  (1..11).to_a.reverse.map do |size|
    text.bytes.map do |e|
      (size <= 10 && Random.srand % size == 0 ? e ^ c : e).chr
    end.join
  end
end

# Helpers

def divergence(scores)
  distance = 0
  scores.each_with_index do |e, i|
    distance += scores[i..-1].select { |x| x > e }.length
  end
  distance / scores.length.to_f
end

score_methods = [
  :letter_space_score, :sorted_frequency_score, :add_letter_and_fequency_score]
shift_methods = [:bit_shift, :rand_shift]

Benchmark.bm(40) do |x|
  score_methods.each do |score_name|
    score_proc = Object.method(score_name)
    shift_methods.each do |shift_name|
      shift_proc = Object.method(shift_name)
      name = "#{score_name}/#{shift_name}"

      x.report(name) do
        N.times { shift_proc.call(TEXT).map(&score_proc) }
      end

      avg = Array.new(N) do
        divergence(shift_proc.call(TEXT).map(&score_proc))
      end.reduce(:+) / N.to_f
      puts "#{name} divergence = #{avg}"
      puts
    end
  end
end
