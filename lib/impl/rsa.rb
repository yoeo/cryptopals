require 'openssl'

require_relative 'common'

module Impl
  # RSA cryptosystem implementation
  class RSA
    include Modulo

    def initialize(key_size = 1024)
      p_prime = OpenSSL::BN.generate_prime(key_size)
      q_prime = OpenSSL::BN.generate_prime(key_size)
      totient = (p_prime - 1) * (q_prime - 1)
      @n_prime = p_prime * q_prime
      @e_value = 3
      @d_value = invmod(@e_value, totient)
    end

    def cls
      self.class
    end

    def self.to_value(text)
      text.unpack('H*')[0].to_i(16)
    end

    def self.to_text(value)
      hex_text = value.to_s(16)
      hex_text = '0' + hex_text if hex_text.length.odd?
      [hex_text].pack('H*').force_encoding('utf-8')
    end

    def drop_private!
      @d_value = nil
    end

    def public_key
      [@e_value, @n_prime]
    end

    def private_key
      [@d_value, @n_prime]
    end

    def encrypt(text)
      value = cls.to_value(text)
      result_text = mod_exp(value, *public_key)
      cls.to_text(result_text)
    end

    def decrypt(text)
      value = cls.to_value(text)
      result_text = mod_exp(value, *private_key)
      cls.to_text(result_text)
    end
  end
end
