require 'openssl'
require 'securerandom'

require_relative 'common'

module Impl
  # RSA cryptosystem implementation
  class RSA
    include Modulo

    def initialize(key_size = 1024)
      p_prime = OpenSSL::BN.generate_prime(key_size)
      q_prime = OpenSSL::BN.generate_prime(key_size)

      totient = (p_prime - 1) * (q_prime - 1)
      @n_modulus = p_prime * q_prime
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
      [@e_value, @n_modulus]
    end

    def private_key
      [@d_value, @n_modulus]
    end

    def encrypt(text)
      value = cls.to_value(text)
      result = mod_exp(value, *public_key)
      cls.to_text(result)
    end

    def decrypt(text)
      value = cls.to_value(text)
      result = mod_exp(value, *private_key)
      cls.to_text(result)
    end
  end

  # Abstract RSA implementation with padding
  class PaddedRSA < RSA
    def encrypt(text)
      super(append_padding(text))
    end

    def decrypt(text)
      remove_padding(super(text))
    end

    def append_padding(_)
      raise NotImplementedError
    end

    def remove_padding(_)
      raise NotImplementedError
    end

    def ps_length(text)
      length = (@n_modulus.bit_length / 8.0).ceil - text.bytes.length - 3
      raise 'modulo too short' unless length > 0
      length
    end

    def strip_padding(text, padding)
      text = text.force_encoding('ASCII-8BIT')
      padding = padding.force_encoding('ASCII-8BIT')
      valid_length = (@n_modulus.bit_length / 8.0).ceil - 1

      raise 'bad padding length' unless text.length == valid_length
      match = text.match(padding)
      raise 'bad padding format' unless match
      match.captures[0].force_encoding('UTF-8')
    end
  end

  # RSA with PCSK1 v1.5 Type 1 padding: used for messages signature
  class SignaturePaddedRSA < PaddedRSA
    def append_padding(text)
      ps = "\xFF" * ps_length(text)
      "\x00\x01#{ps}\x00#{text}"
    end

    def remove_padding(text)
      padding = "^\x00?\x01[\xFF]+\x00(.+)$"
      strip_padding(text, padding)
    end
  end

  # RSA with PCSK1 v1.5 Type 2 padding: used for messages encryption
  class EncryptionPaddedRSA < PaddedRSA
    def append_padding(text)
      size = ps_length(text)
      ps = Array.new(size) { SecureRandom.random_number(1..255).chr }.join
      "\x00\x02#{ps}\x00#{text}"
    end

    def remove_padding(text)
      padding = "^\x00?\x02[^\x00]+\x00(.+)$"
      strip_padding(text, padding)
    end
  end
end
