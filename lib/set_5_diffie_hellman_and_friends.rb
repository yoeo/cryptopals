require_relative 'crypto'
require_relative 'oracle'
require_relative 'impl'

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

  def malicious_srp_client_key(injected_key)
    server = Impl::SRPServer.new('user', 'pass')
    client = Impl::SRPMaliciousClient.new('?', '?', injected_key: injected_key)
    run_protocol(client, server, nb_steps: 5)
  end

  # 38. Simplified SRP man in the middle dictionary attack

  def check_simplified_srp(server_credentials, client_credentials)
    server = Impl::SimpleSRPServer.new(*server_credentials)
    client = Impl::SimpleSRPClient.new(*client_credentials)
    run_protocol(client, server, nb_steps: 5)
  end
end
