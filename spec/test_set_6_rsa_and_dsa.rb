require 'set_6_rsa_and_dsa_part_1'
require 'set_6_rsa_and_dsa_part_2'

RSpec.describe RSAAndDSA do
  describe '41. Implement unpadded message recovery oracle' do
    message = 'bug browser'
    it 'recovers unpadded RSA encrypted message' do
      expect(RSAAndDSA.recover_unpadded(message)).to eq(message)
    end
  end

  describe '42. Bleichenbacher\'s e=3 RSA Attack' do
    message = 'hi mom'

    it 'validates a legit RSA PKCS#1 v1.5 padded signature' do
      expect(RSAAndDSA.legit_signature(message)).to be(true)
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

  describe '44. DSA nonce recovery from repeated nonce' do
    messages_file = 'data/44.txt'
    y =
      '2d026f4bf30195ede3a088da85e398ef869611d0f68f07' \
      '13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8' \
      '5519b1c23cc3ecdc6062650462e3063bd179c2a6581519' \
      'f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430' \
      'f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3' \
      '2971c3de5084cce04a2e147821'.to_i(16)
    x_hash = 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'

    it 'recovers DSA secret key x from reused session key k' do
      expect(RSAAndDSA.reused_key_recovery(messages_file)).to eq([x_hash, y])
    end
  end

  describe '45. DSA parameter tampering' do
    messages = ['Hello, world', 'Goodbye, world']
    DSA_P =
      '800000000000000089e1855218a0e7dac38136ffafa72eda7' \
      '859f2171e25e65eac698c1702578b07dc2a1076da241c76c6' \
      '2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe' \
      'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2' \
      'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87' \
      '1a584471bb1'.to_i(16)

    it 'launches a DOS attack when g = np' do
      n = (0..10).to_a.sample
      expect(RSAAndDSA.force_params([], g: n * DSA_P)).to eq('Timeout')
    end

    it 'creates a DSA god key that validates any message when g = 1 + np' do
      n = (0..10).to_a.sample
      expect(RSAAndDSA.force_params(messages, g: 1 + n * DSA_P)).to be(true)
    end
  end

  describe '46. RSA parity oracle' do
    message =
      'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGd' \
      'W5reSBDb2xkIE1lZGluYQ=='
    result =
      "That's why I found you don't play around with the Funky Cold Medina"

    it 'cracks RSA encrypted message using one bit leak' do
      expect(RSAAndDSA.parity_crack(message)).to eq(result)
    end
  end
end
