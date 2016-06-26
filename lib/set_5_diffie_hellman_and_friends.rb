require 'bigdecimal'

require_relative 'crypto'
require_relative 'impl'
require_relative 'oracle'

# Attacking Diffie Helman key exchange protocol and more
# see http://cryptopals.com/sets/5/
module DiffieHellmanAndFriends
  extend Crypto

  module_function

  # 33. Implement Diffie-Hellman protocol

  def valid_dh_session_key
    keygen_a = Impl::DiffieHellman.new
    keygen_b = Impl::DiffieHellman.new(keygen_a.p, keygen_a.g)

    session_key_a = keygen_a.compute_key(keygen_b.public_key)
    session_key_b = keygen_b.compute_key(keygen_a.public_key)
    session_key_a == session_key_b
  end

  # 34. Inject Diffie-Hellman parameters, MITM

  def run_protocol(node_a, node_b, mitm = nil, nb_steps: 0)
    raise 'nb_steps must be odd' unless nb_steps.odd?
    nb_grouped_steps = (nb_steps - 1) / 2
    data = Array.new(nb_grouped_steps).reduce(nil) do |e|
      if mitm.nil?
        node_b.step(node_a.step(e))
      else
        mitm.step(node_b.step(mitm.step(node_a.step(e))))
      end
    end
    node_a.step(data)
  end

  def dh_echo_working
    node_a = Oracle::Echo.new(Impl::DiffieHellman)
    node_b = Oracle::Echo.new(Impl::DiffieHellman)
    run_protocol(node_a, node_b, nb_steps: 5)
  end

  def dh_mitm_attack
    # Fixed in OpenSSL Diffie-Hellman implementation :)
    node_a = Oracle::Echo.new(Impl::DiffieHellman)
    node_b = Oracle::Echo.new(Impl::DiffieHellman)
    mitm = Oracle::EchoManInTheMiddle.new
    run_protocol(node_a, node_b, mitm, nb_steps: 5)
  end

  # 35. Diffie-Hellman negociated groups man in the middle

  def dh_negotiated_group_working
    node_a = Oracle::EchoNG.new(Impl::DiffieHellman)
    node_b = Oracle::EchoNG.new(Impl::DiffieHellman)
    run_protocol(node_a, node_b, nb_steps: 7)
  end

  def dh_negotiated_group_mitm_attack(g, keys)
    # Also fixed in OpenSSL Diffie-Hellman implementation :)
    node_a = Oracle::EchoNG.new(Impl::DiffieHellman)
    node_b = Oracle::EchoNG.new(Impl::DiffieHellman)
    mitm = Oracle::EchoNGManInTheMiddle.new(g)
    run_protocol(node_a, node_b, mitm, nb_steps: 5)

    keys.any? { |session_key| node_a.right_session_key?(session_key) }
  end

  # 36. Secure Remote Password implementation

  def check_secure_remote_password(server_credentials, client_credentials)
    server = Impl::SRPServer.new(*server_credentials)
    client = Impl::SRPClient.new(*client_credentials)
    run_protocol(client, server, nb_steps: 5)
  end

  # 37. Break SRP, authenticate with bad credentials using a "zero" client key

  def malicious_srp_client_key(identifier, password, injected_key)
    server = Impl::SRPServer.new(identifier, password)
    client = Impl::SRPMaliciousClient.new('?', '?', injected_key: injected_key)
    run_protocol(client, server, nb_steps: 5)
  end

  # 38. Simplified SRP man in the middle dictionary attack

  def check_simplified_srp(server_credentials, client_credentials)
    server = Impl::SimpleSRPServer.new(*server_credentials)
    client = Impl::SimpleSRPClient.new(*client_credentials)
    run_protocol(client, server, nb_steps: 5)
  end

  def crack_simplified_srp_password(identifier, password, dictionary_filename)
    server = Impl::SimpleSRPMaliciousServer.new('?', '?')
    client = Impl::SimpleSRPClient.new(identifier, password)
    run_protocol(client, server, nb_steps: 5)
    server.crack_password(dictionary_filename)
  end

  # 39. RSA implementation

  def check_rsa(text)
    rsa = Impl::RSA.new
    rsa.decrypt(rsa.encrypt(text))
  end

  # 40. Crack RSA broadcast with fixed E = 3

  def chinese_remainer_theorem(encrypted_list, n_list, n_partial_product)
    Array.new(encrypted_list.length) do |i|
      encrypted_list[i] * n_partial_product[i] * Impl::RSA.invmod(
        n_partial_product[i], n_list[i])
    end
  end

  def cubic_root(value)
    (BigDecimal.new(value)**Rational(1, 3)).round
  end

  def compute_encrypted(encrypted_list, n_list)
    n_product = n_list.reduce(:*)
    n_partial_product = n_list.map { |n| n_product.div(n) }

    crt_result = chinese_remainer_theorem(
      encrypted_list, n_list, n_partial_product).reduce(:+) % n_product
    cubic_root(crt_result.to_i)
  end

  def crack_rsa_broadcast(message)
    nb_nodes = 3
    rsa_nodes = Array.new(nb_nodes) { Impl::RSA.new }
    encrypted_list = rsa_nodes.map { |rsa| rsa.encrypt(message) }
    n_list = rsa_nodes.map { |rsa| rsa.public_key[1] }

    Impl::RSA.to_text(compute_encrypted(encrypted_list, n_list))
  end
end
