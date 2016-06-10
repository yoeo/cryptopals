module Impl
  # Common utils
  module Common
    def to_i32(value)
      value & 0xFFFFFFFF
    end

    def rot(word, bits)
      word = to_i32(word)
      to_i32(word << bits | word >> 32 - bits)
    end

    # Merkle-Damgard padding
    def md_pad(length, big_endian: true)
      bit_len = length << 3
      length = (length + 1) % 64
      nb_zeros = 56 - length + ((length >= 56) ? 64 : 0)
      structure = big_endian ? 'Q>1' : 'Q<1'
      [0x80] + [0] * nb_zeros + [bit_len].pack(structure).unpack('C8')
    end
  end

  # Base class for cryptographic hash implementation
  class CryptoHashBase
    include Impl::Common

    def self.hexdigest(*args)
      new.digest(*args).unpack('H*').first
    end
  end
end
