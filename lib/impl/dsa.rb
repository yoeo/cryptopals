require 'digest'
require 'openssl'
require 'securerandom'

require_relative 'common'

module Impl
  # Implements DSA, Digital Signature Algorithm
  class DSA
    P =
      '800000000000000089e1855218a0e7dac38136ffafa72eda7' \
      '859f2171e25e65eac698c1702578b07dc2a1076da241c76c6' \
      '2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe' \
      'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2' \
      'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87' \
      '1a584471bb1'.to_i(16)

    Q = 'f4f47f05794b256174bba6e9b396a7707e563c5b'.to_i(16)

    G =
      '5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119' \
      '458fef538b8fa4046c8db53039db620c094c9fa077ef389b5' \
      '322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047' \
      '0f5b64c36b625a097f1651fe775323556fe00b3608c887892' \
      '878480e99041be601a62166ca6894bdd41a7054ec89f756ba' \
      '9fc95302291'.to_i(16)

    def initialize(p: P, q: Q, g: G)
      @p = p
      @q = q
      @g = g

      @x = rand_mod_q
      @y = @g.to_bn.mod_exp(@x, @p)
    end

    def rand_mod_q
      SecureRandom.random_number(1..@q)
    end

    def sign(text)
      text_hash = Digest::SHA1.hexdigest(text).to_i(16)
      loop do
        k = rand_mod_q
        r = @g.to_bn.mod_exp(k, @p) % @q
        s = k.to_bn.mod_inverse(@q).mod_mul(text_hash + @x * r, @q)
        break [r.to_i, s] unless r.zero? || s.zero?
      end
    end

    def build_validator(u_one, u_two)
      @g.to_bn.mod_exp(u_one, @p) * @y.to_bn.mod_exp(u_two, @p) % @p % @q
    end

    def validate(text, r, s)
      return false unless 0 < r && r < @q && 0 < s && s < @q

      text_hash = Digest::SHA1.hexdigest(text).to_i(16)
      w = s.to_bn.mod_inverse(@q)
      u_one = text_hash * w % @q
      u_two = r * w % @q
      build_validator(u_one, u_two) == r
    end
  end
end
