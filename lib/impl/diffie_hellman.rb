require 'securerandom'

module Impl
  # Diffie-Hellman public key algorithm implementation
  class DiffieHellman
    P =
      'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024' \
      'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd' \
      '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec' \
      '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f' \
      '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361' \
      'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552' \
      'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff' \
      'fffffffffffff'.to_i(16)

    G = 2

    attr_reader :public_key, :p, :g

    def initialize(p = nil, g = nil)
      @p = p || P
      @g = g || G
      @private_key = SecureRandom.random_number(0..@p)
      @public_key = @g.to_bn.mod_exp(@private_key, @p).to_i
    end

    def compute_key(other_public_key)
      other_public_key.to_bn.mod_exp(@private_key, @p).to_i
    end
  end
end
