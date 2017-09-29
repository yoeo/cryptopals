require 'set_2_block_crypto'

RSpec.describe BlockCrypto do
  describe '9. Implement PKCS#7 padding' do
    input = 'YELLOW SUBMARINE'
    block_size = 20
    output = "YELLOW SUBMARINE\x04\x04\x04\x04"
    it 'appends padding to the input' do
      expect(BlockCrypto.append_pkcs_7_padding(input, block_size)).to eq(output)
    end
  end

  describe '10. Implement CBC mode' do
    filename = 'data/10.txt'
    key = 'YELLOW SUBMARINE'
    iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    output = "I'm back and I'm ringin' the bell "
    it 'implements CBC mode decryption from AES-ECB cipher' do
      expect(
        BlockCrypto.manually_decrypt_cbc(filename, key, iv).split("\n")[0]
      ).to eq(output)
    end
  end

  describe '11. An ECB/CBC detection oracle' do
    it 'detects ECB or CBC encryption mode' do
      expect(BlockCrypto.guess_encryption_mode).to be true
    end
  end

  describe '12. Byte-at-a-time ECB decryption (Simple)' do
    input =
      'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' \
      'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' \
      'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg' \
      'YnkK'
    output = "Rollin' in my 5.0"
    it 'recovers the plain text from an ECB oracle' do
      expect(BlockCrypto.byte_by_byte_guess(input).split("\n")[0]).to eq(output)
    end
  end

  describe '13. ECB cut-and-paste' do
    output = 'admin'
    it 'alters ECB encrypted data' do
      expect(BlockCrypto.alter_ecb_encrypted_data['role']).to eq(output)
    end
  end

  describe '14. Byte-at-a-time ECB decryption (Harder)' do
    input =
      'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' \
      'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' \
      'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg' \
      'YnkK'
    output = "Rollin' in my 5.0"

    it 'recovers the first byte of plain text from a random ECB oracle' do
      expect(
        BlockCrypto.random_byte_guess(input, nb_bytes: 1).split("\n")[0]
      ).to eq(output[0])
    end
    it 'recovers the plain text from a random ECB oracle', slow: true do
      expect(BlockCrypto.random_byte_guess(input).split("\n")[0]).to eq(output)
    end
  end

  describe '15. PKCS#7 padding validation' do
    good_padding = ["ICE ICE BABY\x04\x04\x04\x04"]
    bad_padding = [
      "ICE ICE BABY\x05\x05\x05\x05", "ICE ICE BABY\x01\x02\x03\x04"
    ]
    output = 'ICE ICE BABY'

    it 'strips valid padding' do
      good_padding.map do |e|
        expect(BlockCrypto.strip_pkcs_7_padding(e)).to eq(output)
      end
    end
    it 'fails while stripping bad padding' do
      bad_padding.map do |e|
        expect { BlockCrypto.strip_pkcs_7_padding(e) }.to raise_exception(
          'bad padding'
        )
      end
    end
  end

  describe '16. CBC bitflipping attacks' do
    it 'decrypts CBC encrypted data' do
      expect(BlockCrypto.bitflip_cbc_encrypted_data).to be true
    end
  end
end
