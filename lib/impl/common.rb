require 'openssl'

module OpenSSL
  # Patch OpenSSL::BN, add integer division
  class BN
    alias bit_length num_bits

    def div(denominator)
      (self / denominator)[0]
    end
  end
end

module Impl
  NIST_PRIME =
    'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024' \
    'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd' \
    '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec' \
    '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f' \
    '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361' \
    'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552' \
    'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff' \
    'fffffffffffff'.to_i(16)

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
      nb_zeros = 56 - length + (length >= 56 ? 64 : 0)
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

  # FIXME: class unneeded, see bn.mod_inverse
  # Operation on numbers with a modulo
  module Modulo
    module_function

    def mod_exp(base, exponent, modulo)
      base.to_bn.mod_exp(exponent, modulo)
    end

    def extended_gcd(a, n)
      t = 0
      new_t = 1
      r = n
      new_r = a
      loop do
        return [r, t] if new_r.zero?
        quotient = r.div(new_r)
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
      end
    end

    def invmod(a, n)
      r, t = extended_gcd(a, n)
      raise 'the modulo is not invertible' unless r == 1
      t + (t < 0 ? n : 0)
    end
  end
end
