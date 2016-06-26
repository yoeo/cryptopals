require 'openssl'

module Impl
  # RSA cryptosystem implementation
  class RSA
    def initialize(key_size = 1024)
      p_prime = OpenSSL::BN.generate_prime(key_size)
      q_prime = OpenSSL::BN.generate_prime(key_size)
      totient = (p_prime - 1) * (q_prime - 1)
      @n_prime = p_prime * q_prime
      @e_value = 3
      @d_value = invmod(@e_value, totient)
    end

    def extended_gcd(a, n)
      t = 0
      new_t = 1
      r = n
      new_r = a
      loop do
        return [r, t] if new_r == 0
        quotient = (r.to_bn / new_r)[0]
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
      end
    end

    def invmod(a, n)
      r, t = extended_gcd(a, n)
      raise 'the modulo is not invertible' unless r == 1
      t + (t < 0 ? n : 0)
    end

    def public_key
      [@e_value, @n_prime]
    end

    def private_key
      [@d_value, @n_prime]
    end

    def encrypt(text)
      to_value(text).to_bn.mod_exp(*public_key)
    end

    def decrypt(value)
      to_text(value.to_bn.mod_exp(*private_key))
    end

    def to_value(text)
      text.unpack('H*')[0].to_i(16)
    end

    def to_text(value)
      hex_text = value.to_s(16)
      hex_text = '0' + hex_text if hex_text.length.odd?
      [hex_text].pack('H*').force_encoding('utf-8')
    end
  end
end
