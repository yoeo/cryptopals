require_relative 'common'

module Impl
  # MT19937 PRNG implementation: Mersenne twister with a period of 2**19937
  class MT19937
    include Impl::Common

    def initialize(seed)
      @index = 624
      @mt = [seed] + [0] * 623
      (1...624).each do |i|
        @mt[i] = to_i32(1_812_433_253 * (@mt[i - 1] ^ @mt[i - 1] >> 30) + i)
      end
    end

    def rand
      twist if @index >= 624
      value = @mt[@index]
      @index += 1
      shift(value)
    end

    private

    def twist_value(i)
      to_i32((@mt[i] & 0x80000000) + (@mt[(i + 1) % 624] & 0x7fffffff))
    end

    def update_mt(i)
      value = twist_value(i)
      @mt[i] = @mt[(i + 397) % 624] ^ value >> 1
      @mt[i] = @mt[i] ^ 0x9908b0df if value.odd?
    end

    def twist
      624.times { |i| update_mt(i) }
      @index = 0
    end

    def shift(value)
      value = value ^ value >> 11
      value = value ^ value << 7 & 2_636_928_640
      value = value ^ value << 15 & 4_022_730_752
      value = value ^ value >> 18

      to_i32(value)
    end
  end

  # Clone a MT19937 PRNG
  class MT19937Clone < MT19937
    def initialize(numbers)
      raise 'bad size' unless numbers.length >= 2 * 624 + 10
      copy_state(numbers)
    end

    private

    def copy_state(numbers)
      size = numbers.length
      mt_candidates = numbers.map { |e| unshift(e) }
      624.times do |i|
        @index = 624
        @mt = mt_candidates[i...i + 624]
        following = Array.new(size - i - 624) { rand }
        break if following == numbers[i + 624...size]
      end
    end

    def undo_xor_rshift(value, offset)
      copy = value
      until copy.zero?
        copy >>= offset
        value ^= copy
      end
      value
    end

    def undo_xor_lshift(value, offset, mask)
      chunk_mask = (1 << offset) - 1
      (0..32 / offset).each do |n|
        chunk = value >> (n * offset) & chunk_mask
        value ^= chunk << ((n + 1) * offset) & mask
      end
      value
    end

    def unshift(value)
      value = undo_xor_rshift(value, 18)
      value = undo_xor_lshift(value, 15, 4_022_730_752)
      value = undo_xor_lshift(value, 7, 2_636_928_640)
      value = undo_xor_rshift(value, 11)
      to_i32(value)
    end
  end
end
