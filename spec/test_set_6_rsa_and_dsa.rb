require 'set_6_rsa_and_dsa'

RSpec.describe RSAAndDSA do
  describe '41. Implement unpadded message recovery oracle' do
    message = 'bug browser'
    it 'recovers unpadded RSA encrypted message' do
      expect(RSAAndDSA.recover_unpadded(message)).to eq(message)
    end
  end

  describe '42. Bleichenbacher\'s e=3 RSA Attack' do
    message = 'hi mom'

    it 'validates a PKCS#1 v1.5 padded hash' do
      padded_hash = File.read(
        'data/42_message.txt.pkcs1'
      ).force_encoding('ASCII-8BIT')
      expect(RSAAndDSA.valid_pkcs1(padded_hash, message)).to be(true)
    end

    it 'generates a fake signature for an e=3 RSA public key' do
      expect(RSAAndDSA.fake_signature(message)).to be(true)
    end
  end

  describe '43. DSA key recovery from nonce' do
    right_message = 'Olive'
    wrong_message = '0live'

    message =
      "For those that envy a MC it can be hazardous to your health\n" \
      "So be friendly, a matter of life and death, just like a etch-a-sketch\n"
    r = '548099063082341131477253921760299949438196259240'.to_i
    s = '857042759984254168557880549501802188789837994940'.to_i
    y =
      '84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4' \
      'abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004' \
      'e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed' \
      '1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b' \
      'bb283e6633451e535c45513b2d33c99ea17'.to_i(16)
    x_hash = '0954edd5e0afe5542a4adf012611a91912a3ec16'

    it 'validates well signed message' do
      expect(RSAAndDSA.dsa_signing(right_message, right_message)).to be(true)
    end

    it 'doesn\'t validate bad signed message' do
      expect(RSAAndDSA.dsa_signing(wrong_message, right_message)).to be(false)
    end

    it 'recovers DSA secret key x from insecure session key k' do
      expect(RSAAndDSA.dsa_key_recovered(message, r, s, y)).to eq(x_hash)
    end
  end
end
