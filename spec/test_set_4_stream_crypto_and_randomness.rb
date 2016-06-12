require 'set_4_stream_crypto_and_randomness'

RSpec.describe StreamCryptoAndRandomness do
  describe '25. Break "random access read/write" AES CTR' do
    filename = 'data/25.txt'
    key_text = 'YELLOW SUBMARINE'
    first_line = "I'm back and I'm ringin' the bell "

    it 'attacks CTR using random access' do
      expect(
        StreamCryptoAndRandomness.ctr_random_access_attack(
          filename, key_text).split("\n")[0]).to eq(first_line)
    end
  end

  describe '26. CTR bitflipping' do
    it 'modifies CTR encrypted text by flipping bits' do
      expect(StreamCryptoAndRandomness.bitflip_ctr_encrypted_data).to be true
    end
  end

  describe '27. Recover the key from CBC with IV=Key' do
    input = 'hidden'
    output =
      'comment1=cooking%20MCs;userdata=hidden;' \
      'comment2=%20like%20a%20pound%20of%20bacon'

    it 'guesses the encryption key when key and IV are the same' do
      expect(StreamCryptoAndRandomness.recover_cbc_key(input)).to eq(output)
    end
  end

  describe '28. Implement a SHA-1 keyed MAC' do
    matching_mac = [
      # [key, message, MAC]
      %w(0123456789abcdef mass c4fb16e8442d644eb175261382e3b12aeb4e3658),
      %w(AfZG25RzE5/Hz86K local ccae9dfc126aa7fbe763500193826bc34cbfb079)
    ]
    unmatching_mac = [
      # [key, message, MAC]
      %w(0123456789abcdef mess c4fb16e8442d644eb175261382e3b12aeb4e3658),
      %w(AfZG25RzE5-Hz86K local ccae9dfc126aa7fbe763500193826bc34cbfb079)
    ]

    it 'works when the MAC matches' do
      expect(matching_mac.all? do |key_text, text, digest_text|
        StreamCryptoAndRandomness.sha1_mac(key_text, text) == digest_text
      end).to be true
    end

    it 'fails when the MAC doesn\'t match' do
      expect(unmatching_mac.none? do |key_text, text, digest_text|
        StreamCryptoAndRandomness.sha1_mac(key_text, text) == digest_text
      end).to be true
    end
  end

  describe '29. Break a SHA-1 keyed MAC using length extension' do
    it 'creates a valid SHA-1 MAC from tempered data' do
      expect(StreamCryptoAndRandomness.break_sha1_mac).to be true
    end
  end

  describe '30. Break an MD4 keyed MAC using length extension' do
    matching_mac = [
      # [key, message, MAC]
      %w(0123456789abcdef mass 556fda94caca455accf6420e40b19793),
      %w(AfZG25RzE5/Hz86K local 99653ea6ebab5b27be0ce1a5dc945dec)
    ]
    unmatching_mac = [
      # [key, message, MAC]
      %w(0123456789abcdef mess 556fda94caca455accf6420e40b19793),
      %w(AfZG25RzE5-Hz86K local 99653ea6ebab5b27be0ce1a5dc945dec)
    ]

    it 'works when the MAC matches' do
      expect(matching_mac.all? do |key_text, text, digest_text|
        StreamCryptoAndRandomness.md4_mac(key_text, text) == digest_text
      end).to be true
    end

    it 'fails when the MAC doesn\'t match' do
      expect(unmatching_mac.none? do |key_text, text, digest_text|
        StreamCryptoAndRandomness.md4_mac(key_text, text) == digest_text
      end).to be true
    end

    it 'creates a valid MD4 MAC from tempered data' do
      expect(StreamCryptoAndRandomness.break_md4_mac).to be true
    end
  end

  describe '31. Implement and break HMAC-SHA1 with an artificial timing leak' do
    matching_mac = [
      # [key, message, MAC]
      %w(0123456789abcdef mass f69584b9fc6c4a8175d89a7ea128c70eb74ebf7f),
      %w(AfZG25RzE5/Hz86K local 4dbd75bba7c557ce1de47df630de1fa51832ded8)
    ]

    it 'works when the HMAC matches' do
      expect(matching_mac.all? do |key_text, text, digest_text|
        StreamCryptoAndRandomness.sha1_hmac(key_text, text) == digest_text
      end).to be true
    end

    it 'finds the first byte of the HMAC from timing leak' do
      expect(
        StreamCryptoAndRandomness.partial_timed_sha1_hmac(
          'hidden.txt')).to eq(200)
    end

    it 'creates a valid HMAC from timing leak', slow: true do
      expect(
        StreamCryptoAndRandomness.full_timed_sha1_hmac(
          'hidden.txt')).to eq(200)
    end
  end

  describe '32. Break HMAC-SHA1 with a slightly less artificial timing leak' do
    it 'finds the first byte of the HMAC from a tiny timing leak' do
      expect(
        StreamCryptoAndRandomness.partial_milli_timed_sha1_hmac(
          'hidden.txt')).to eq(200)
    end

    it 'creates a valid HMAC from a tiny timing leak', slow: true do
      expect(
        StreamCryptoAndRandomness.full_milli_timed_sha1_hmac(
          'hidden.txt')).to eq(200)
    end
  end
end
