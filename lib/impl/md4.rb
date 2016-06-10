require_relative 'common'

module Impl
  # MD4 hash implementation
  class MD4 < CryptoHashBase
    def digest(text)
      bytes = text.bytes
      reset
      feed(bytes + md_pad(bytes.length, big_endian: false))
      result
    end

    private

    def reset
      @state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
      @round_data = [
        [0, [0, 4, 8, 12], [0, 1, 2, 3], [3, 7, 11, 19]],
        [0x5a827999, [0, 1, 2, 3], [0, 4, 8, 12], [3, 5, 9, 13]],
        [0x6ed9eba1, [0, 2, 1, 3], [0, 8, 4, 12], [3, 9, 11, 15]]
      ]
    end

    def result
      @state.pack('V4')
    end

    def function(round_num, x, y, z)
      case round_num
      when 0 # function F
        x & y | x.^(0xFFFFFFFF) & z
      when 1 # function G
        x & y | x & z | y & z
      when 2 # function H
        x ^ y ^ z
      end
    end

    def shift_state(state, j)
      (j == 1 ? [] : state[1 - j..-1]) + state[0...-j]
    end

    def pick(round_num, block, i, j)
      complement, i_indices, j_indices, offsets = @round_data[round_num]
      [complement + block[i_indices[i] + j_indices[j]], offsets[j]]
    end

    def round(round_num, state, block)
      (0..3).to_a.repeated_permutation(2) do |i, j|
        value, offset = pick(round_num, block, i, j)
        state[-j] = rot(
          state[-j] + function(round_num, *shift_state(state, j)) + value,
          offset)
      end
      state
    end

    def feed(bytes)
      bytes.each_slice(64) do |block|
        block = block.pack('C64').unpack('V16')
        state = @state.dup
        (0..2).each do |i|
          state = round(i, state, block)
        end
        @state = @state.zip(state).map { |x, y| to_i32(x + y) }
      end
    end
  end

  # Compute the state of the SHA-1 hash generator
  class ExtensibleMD4 < MD4
    def initialize(prev_length, mac_text)
      @prev_length = prev_length
      @prev_state = [mac_text].pack('H32').unpack('V4')
    end

    def digest(text)
      bytes = text.bytes
      reset
      @state = @prev_state.dup
      full_length = @prev_length + previous_padding.length + bytes.length
      feed(bytes + md_pad(full_length, big_endian: false))
      result
    end

    def previous_padding
      md_pad(@prev_length, big_endian: false)
    end
  end
end
