require 'set_5_diffie_hellman_and_friends'

RSpec.describe DiffieHellmanAndFriends do
  NIST_PRIME =
    'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024' \
    'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd' \
    '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec' \
    '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f' \
    '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361' \
    'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552' \
    'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff' \
    'fffffffffffff'.to_i(16)

  describe '33. Implement Diffie-Hellman' do
    it 'ensures that the Diffie-Hellman session keys are valid' do
      expect(DiffieHellmanAndFriends.valid_dh_session_key).to be true
    end
  end

  description_34 =
    '34. Implement a MITM key-fixing attack on Diffie-Hellman with parameter ' \
    'injection'
  describe description_34 do
    it 'checks the Echo protocol based on Diffie-Hellman' do
      expect(DiffieHellmanAndFriends.dh_echo_working[1]).to be true
    end
    it 'performs a man in the middle attack on Diffie-Hellman' do
      expect(DiffieHellmanAndFriends.dh_mitm_attack[1]).to be true
    end
  end

  description_35 =
    '35. Implement DH with negotiated groups, and break with malicious "g" ' \
    'parameters'
  describe description_35 do
    P = NIST_PRIME
    it 'checks the negotiated groups protocol based on Diffie-Hellman' do
      expect(DiffieHellmanAndFriends.dh_negotiated_group_working[1]).to be true
    end
    it 'confirms that generated session key = 1 when injected g = 1' do
      expect(
        DiffieHellmanAndFriends.dh_negotiated_group_mitm_attack(1, [1])
      ).to be true
    end
    it 'confirms that generated session key = 0 when injected g = p' do
      expect(
        DiffieHellmanAndFriends.dh_negotiated_group_mitm_attack(P, [0])
      ).to be true
    end
    it 'confirms that session key = (1 or p - 1) when injected g = p - 1' do
      expect(
        DiffieHellmanAndFriends.dh_negotiated_group_mitm_attack(
          P - 1, [1, P - 1]
        )
      ).to be true
    end
  end

  describe '36. Implement Secure Remote Password (SRP)' do
    matching_credentials = [
      [%w(pablo 12345), %w(pablo 12345)],
      [%w(picasso password), %w(picasso password)]
    ]

    unmatching_credentials = [
      [%w(pablo 12345), %w(pablo 12346)],
      [%w(picasso password), %w(pycasso password)]
    ]

    it 'authenticates when credentials matches' do
      expect(
        matching_credentials.all? do |server_credentials, client_credentials|
          DiffieHellmanAndFriends.check_secure_remote_password(
            server_credentials, client_credentials
          )[1]
        end
      ).to be true
    end

    it "fails to authenticate when credentials doesn't match" do
      expect(
        unmatching_credentials.none? do |server_credentials, client_credentials|
          DiffieHellmanAndFriends.check_secure_remote_password(
            server_credentials, client_credentials
          )[1]
        end
      ).to be true
    end
  end

  describe '37. Break SRP with a zero key' do
    N = NIST_PRIME
    identifier = 'user'
    password = 'pass'

    it 'confirms that session value is 0 when injected client key is 0' do
      expect(
        DiffieHellmanAndFriends.malicious_srp_client_key(
          identifier, password, 0
        )[1]
      ).to be true
    end

    it 'confirms that session value is 0 when injected client key is N' do
      expect(
        DiffieHellmanAndFriends.malicious_srp_client_key(
          identifier, password, N
        )[1]
      ).to be true
    end

    it 'confirms that session value is 0 when injected client key is x * N' do
      injected_key = N * (0..10).to_a.sample
      expect(
        DiffieHellmanAndFriends.malicious_srp_client_key(
          identifier, password, injected_key
        )[1]
      ).to be true
    end
  end

  describe '38. Offline dictionary attack on simplified SRP' do
    matching_credentials = [
      [%w(pablo 12345), %w(pablo 12345)],
      [%w(picasso password), %w(picasso password)]
    ]

    unmatching_credentials = [
      [%w(pablo 12345), %w(pablo 12346)],
      [%w(picasso password), %w(pycasso password)]
    ]

    it 'authenticates when simplified SRP credentials matches' do
      expect(
        matching_credentials.all? do |server_credentials, client_credentials|
          DiffieHellmanAndFriends.check_secure_remote_password(
            server_credentials, client_credentials
          )[1]
        end
      ).to be true
    end

    it "fails to authenticate when simplified SRP credentials doesn't match" do
      expect(
        unmatching_credentials.none? do |server_credentials, client_credentials|
          DiffieHellmanAndFriends.check_secure_remote_password(
            server_credentials, client_credentials
          )[1]
        end
      ).to be true
    end

    it 'cracks the password using MITM and dict attack on simplified SRP' do
      identifier = 'user'
      password = 'pass'
      dictionary_filename = 'data/38_dictionary_10_000_passwords.txt'
      expect(
        DiffieHellmanAndFriends.crack_simplified_srp_password(
          identifier, password, dictionary_filename
        )
      ).to eq(password)
    end
  end

  describe '39. Implement RSA' do
    message = 'There are two annoying things about implementing RSA.'

    it 'encrypts and decrypts a message using RSA cryptosystem' do
      expect(DiffieHellmanAndFriends.check_rsa(message)).to eq(message)
    end
  end

  describe '40. Implement an E=3 RSA Broadcast attack' do
    message = "Assume you're a Javascript programmer."

    it 'cracks the broadcast RSA encrypted message when E is 3' do
      expect(
        DiffieHellmanAndFriends.crack_rsa_broadcast(message)
      ).to eq(message)
    end
  end
end
