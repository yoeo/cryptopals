require 'set_1_basics'

RSpec.describe Basics do
  describe '1. Convert hex to base64' do
    input =
      '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f' \
      '6e6f7573206d757368726f6f6d'
    output =
      'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    it 'encodes hex to base64' do
      expect(Basics.hex_to_base64(input)).to eq(output)
    end
  end

  describe '2. Fixed XOR' do
    x = '1c0111001f010100061a024b53535009181c'
    y = '686974207468652062756c6c277320657965'
    result = '746865206b696420646f6e277420706c6179'

    it 'runs XOR' do
      expect(Basics.xor_hex_values(x, y)).to eq(result)
    end
  end

  describe '3. Single-byte XOR cipher' do
    input =
      '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    output = 'Cooking MC\'s like a pound of bacon'
    it 'decrypts simple XOR' do
      expect(Basics.byte_xor(input)).to eq(output)
    end
  end

  describe '4. Detect single-character XOR' do
    input_filename = 'data/4.txt'
    output = "Now that the party is jumping\n5"
    it 'finds encryped line' do
      expect(Basics.detect_byte_xor(input_filename)).to eq(output)
    end
  end

  describe '5. Implement repeating-key XOR' do
    input =
      "Burning 'em, if you ain't quick and nimble" \
      "\nI go crazy when I hear a cymbal"
    key = 'ICE'
    output =
      '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263242727' \
      '65272a282b2f20430a652e2c652a3124333a653e2b2027630c692b2028316528632630' \
      '2e27282f'
    it 'encrypts a text with a key' do
      expect(Basics.xor_encrypt(input, key)).to eq(output)
    end
  end

  describe '6. Break repeating-key XOR' do
    input_a = 'this is a test'.bytes
    input_b = 'wokka wokka!!!'.bytes
    result = 37
    filename = 'data/6.txt'
    first_line = "I'm back and I'm ringin' the bell "

    it 'checks the Hamming distance' do
      expect(Basics.hamming_distance(input_a, input_b)).to eq(result)
    end

    it 'breaks a repeating key XOR', slow: true do
      expect(
        Basics.repeating_xor_crack(filename).split("\n")[0]).to eq(
          first_line)
    end
  end

  describe '7. AES in ECB mode' do
    filename = 'data/7.txt'
    key_text = 'YELLOW SUBMARINE'
    first_line = "I'm back and I'm ringin' the bell "
    it 'decripts AES-ECB encrypted file' do
      expect(
        Basics.decrypt_aes_ecb_file(filename, key_text).split("\n")[0]).to eq(
          first_line)
    end
  end

  describe '8. Detect AES in ECB mode' do
    filename = 'data/8.txt'
    line_number = 132
    it 'finds the AES-ECB encrypted line' do
      expect(Basics.detect_aes_ecb(filename)).to eq(line_number)
    end
  end
end
