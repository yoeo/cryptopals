require 'openssl'
require 'securerandom'

require_relative 'common'

module Impl
  # Secure Remote Password protocol implementation
  class SecureRemotePassword
    N = NIST_PRIME
    G = 2
    K = 3

    def initialize(identifier, password, n = nil, g = nil, k = nil)
      @identifier = identifier
      @password = password
      @n = n || N
      @g = g || G
      @k = k || K
    end

    def state_machine
      %w(client_key server_key client_proof server_proof client_authenticated)
    end

    def step(args = nil)
      step_i, step_args = args || [0, []]
      [step_i + 1, send(state_machine[step_i], *step_args)]
    end

    def hash_values(*args)
      text = args.map(&:to_s).reduce(:+)
      OpenSSL::Digest::SHA256.hexdigest(text).to_i(16)
    end

    def rand_value(bit_length = 1024)
      SecureRandom.random_number(1 << bit_length)
    end

    def build_proof(key, salt)
      OpenSSL::HMAC.hexdigest(
        OpenSSL::Digest::SHA1.new, key.to_s, salt.to_s).to_i(16)
    end

    def pow(x, a, n)
      x.to_bn.mod_exp(a, n)
    end
  end

  # Secure Remote Password server implementation
  class SRPServer < SecureRemotePassword
    def initialize(*args)
      super(*args)
      @salt = rand_value(64)
      x_private_key = hash_values(@salt, @identifier, @password)
      @verifier = pow(@g, x_private_key, @n)
    end

    def server_key(_identifier, a_key)
      # the client private key will be incorrect if the identifier is wrong
      @a_key = a_key
      @b_value = rand_value
      @b_key = (@k * @verifier + pow(@g, @b_value, @n)) % @n
      [@salt, @b_key]
    end

    def server_proof(client_proof_value)
      u_hash = hash_values(@a_key, @b_key)
      session_value = pow(@a_key * pow(@verifier, u_hash, @n), @b_value, @n)
      key_for_session = hash_values(session_value)

      [build_proof(key_for_session, @salt) == client_proof_value ? 'OK' : 'KO']
    end
  end

  # Secure Remote Password clinet implementation
  class SRPClient < SecureRemotePassword
    def client_key
      @a_value = rand_value
      @a_key = pow(@g, @a_value, @n)
      [@identifier, @a_key]
    end

    def client_proof(salt, b_key)
      u_hash = hash_values(@a_key, b_key)
      x_private_key = hash_values(salt, @identifier, @password)

      session_value = pow(
        b_key - @k * pow(@g, x_private_key, @n),
        @a_value + u_hash * x_private_key, @n)
      key_for_session = hash_values(session_value)

      [build_proof(key_for_session, salt)]
    end

    def client_authenticated(result)
      result == 'OK'
    end
  end

  # SRP malicious client that authenticates without knowing the credentials
  class SRPMaliciousClient < SRPClient
    def initialize(*args, injected_key: 0)
      super(*args)
      raise 'bad injected key' unless injected_key % @n == 0
      @injected_key = injected_key
    end

    def client_key
      identifier, _a_key = super()
      [identifier, @injected_key]
    end

    def client_proof(salt, _b_key)
      # session key doesn't depend on indentifier or password value
      session_value = 0
      key_for_session = hash_values(session_value)
      [build_proof(key_for_session, salt)]
    end
  end

  # Simplified SRP server
  class SimpleSRPServer < SRPServer
    def server_key(_identifier, a_key)
      # the client private key will be incorrect if the identifier is wrong
      @a_key = a_key
      @b_value = rand_value
      @b_key = pow(@g, @b_value, @n)
      @u_hash = rand_value(128)
      [@salt, @b_key, @u_hash]
    end

    def server_proof(client_proof_value)
      session_value = pow(@a_key * pow(@verifier, @u_hash, @n), @b_value, @n)
      key_for_session = hash_values(session_value)

      [build_proof(key_for_session, @salt) == client_proof_value ? 'OK' : 'KO']
    end
  end

  # Simplified SRP client
  class SimpleSRPClient < SRPClient
    def client_proof(salt, b_key, u_hash)
      x_private_key = hash_values(salt, @identifier, @password)
      session_value = pow(b_key, @a_value + u_hash * x_private_key, @n)
      key_for_session = hash_values(session_value)

      [build_proof(key_for_session, salt)]
    end

    def client_authenticated(result)
      result == 'OK'
    end
  end
end
