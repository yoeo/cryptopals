require 'set_3_block_and_stream_crypto'

RSpec.describe BlockAndStreamCrypto do
  describe '17. The CBC padding oracle' do
    filename = 'data/17_custom.txt'
    output = '00000'

    it 'attacks CBC using padding information' do
      expect(
        BlockAndStreamCrypto.cbc_padding_attack(filename)[0..4]
      ).to eq(output)
    end
  end

  describe '18. Implement CTR, the stream cipher mode' do
    encoded =
      'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    key_text = 'YELLOW SUBMARINE'
    nonce_text = "\x00" * 8
    output = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

    it 'implements CTR mode using ECB' do
      expect(
        BlockAndStreamCrypto.decrypt_ctr_mode(encoded, key_text, nonce_text)
      ).to eq(output)
    end
  end

  describe '19. Break fixed-nonce CTR mode using substitutions' do
    filename = 'data/19_custom.txt'
    output = 'a terrible beauty is born.'

    it 'attacks text encrypted with same nonce in CTR mode' do
      expect(
        BlockAndStreamCrypto.ctr_substitution_attack(filename)[-1].downcase
      ).to eq(output)
    end
  end

  describe '20. Break fixed-nonce CTR statistically' do
    filename = 'data/20.txt'
    output = 'and we outta here / yo, what happened to peace? / pea'

    it 'attacks same nonce in CTR as a repeating-key XOR' do
      expect(
        BlockAndStreamCrypto.ctr_repeating_xor_attack(filename)[-1].downcase
      ).to eq(output)
    end
  end

  describe '21. Implement the MT19937 Mersenne Twister RNG' do
    seed = 92
    nb_elements = 4
    output = [3_804_827_770, 3_925_700_650, 3_386_932_035, 1_026_824_210]

    it 'implements a pseudorandom numbers generators' do
      expect(BlockAndStreamCrypto.mt19937_rand(seed, nb_elements)).to eq(output)
    end
  end

  describe '22. Crack an MT19937 seed' do
    it 'guesses the seed of a pseudorandom numbers generators' do
      expect(BlockAndStreamCrypto.guess_mt19937_seed).to be true
    end
  end

  describe '23. Clone an MT19937 RNG from its output' do
    it 'creates a copy of the state of a PRNG' do
      expect(BlockAndStreamCrypto.clone_mt19937).to be true
    end
  end

  describe '24. Create the MT19937 stream cipher and break it' do
    filename = 'data/24_custom.txt'

    it 'creates a PRNG stream cipher' do
      expect(BlockAndStreamCrypto.mt19937_encrypt_decrypt(filename)).to be true
    end
    it 'creates cracks the PRNG stream cipher' do
      expect(BlockAndStreamCrypto.crack_mt19937_cipher).to be true
    end
    it 'checks if a token comes from a MT19937 PRNG seeded with current time' do
      expect(BlockAndStreamCrypto.detect_mt19937_token).to be true
    end
  end
end
