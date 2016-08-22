require_relative 'common'

# Custom implementation of Cryptographic Hash algos
module Impl
  # SHA1 Implementation
  class SHA1 < CryptoHashBase
    def digest(text)
      bytes = text.bytes
      reset
      feed(bytes + md_pad(bytes.length))
      result
    end

    private

    def reset
      @blocks = Array.new(64, 0)
      @state = [0x67452301, 0xeFcdab89, 0x98badcFe, 0x10325476, 0xc3d2e1F0]
    end

    def feed(message_array)
      (0...message_array.length).each do |i|
        @blocks[i % 64] = message_array[i]
        process_message_block if ((i + 1) % 64).zero?
      end
    end

    def slide_map(value)
      (0..3).map { |i| 0xFF & (value >> 24 - 8 * i) }
    end

    def result
      @state.pack('N5')
    end

    def mix_values(i, b, c, d)
      case i
      when 0
        (b & c) | ((~b) & d)
      when 1, 3
        b ^ c ^ d
      when 2
        (b & c) | (b & d) | (c & d)
      end
    end

    def mix_state(i, t, state, w, k)
      a, b, c, d, e = state
      tmp = to_i32(rot(a, 5) + mix_values(i, b, c, d) + e + w[t] + k[i])
      [tmp, a, rot(b, 30), c, d]
    end

    def transform(state, w, k)
      (0...4).each do |i|
        (20 * i...20 * (i + 1)).each do |t|
          state = mix_state(i, t, state, w, k)
        end
      end
      state
    end

    def w_values
      Array.new(16) do |t|
        Array.new(4) do |i|
          to_i32(@blocks[t * 4 + i] << 24 - 8 * i)
        end.reduce(:|)
      end + Array.new(64, 0)
    end

    def process_message_block
      k = [0x5a827999, 0x6ed9eba1, 0x8F1bbcdc, 0xca62c1d6]
      w = w_values
      (16...80).each do |t|
        w[t] = rot([3, 8, 14, 16].map { |i| w[t - i] }.reduce(:^), 1)
      end
      @state = @state.zip(transform(@state, w, k)).map { |x, y| to_i32(x + y) }
    end
  end

  # Compute the state of the SHA-1 hash generator
  class ExtensibleSHA1 < SHA1
    def initialize(prev_length, mac_text)
      @prev_length = prev_length
      @prev_state = mac_text.chars.each_slice(8).map { |e| e.join.to_i(16) }
      @prev_state = [mac_text].pack('H40').unpack('N5')
    end

    def digest(text)
      bytes = text.bytes
      reset
      @state = @prev_state.dup
      full_length = @prev_length + previous_padding.length + bytes.length
      feed(bytes + md_pad(full_length))
      result
    end

    def previous_padding
      md_pad(@prev_length)
    end
  end
end
