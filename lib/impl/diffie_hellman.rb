require 'securerandom'

require_relative 'common'

module Impl
  # Diffie-Hellman public key algorithm implementation
  class DiffieHellman
    P = NIST_PRIME
    G = 2

    attr_reader :public_key, :p, :g

    def initialize(p = nil, g = nil)
      @p = p || P
      @g = g || G
      @private_key = SecureRandom.random_number(@p)
      @public_key = @g.to_bn.mod_exp(@private_key, @p).to_i
    end

    def compute_key(other_public_key)
      other_public_key.to_bn.mod_exp(@private_key, @p).to_i
    end
  end
end
