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
        'data/42_message.txt.pkcs1').force_encoding('ASCII-8BIT')
      expect(RSAAndDSA.valid_pkcs1(padded_hash, message)).to be(true)
    end

    it 'generates a fake signature for an e=3 RSA public key' do
      expect(RSAAndDSA.fake_signature(message)).to be(true)
    end
  end

  describe '43. DSA key recovery from nonce' do
    it 'recovers DSA key' do
      expect(RSAAndDSA.dsa_key_recovered).to be(true)
    end
  end
end
