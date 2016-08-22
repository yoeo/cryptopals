require 'base64'

require_relative 'crypto'
require_relative 'impl'
require_relative 'oracle'

# Attacking block crypto and random number generators
# see http://cryptopals.com/sets/3/
module BlockAndStreamCrypto
  extend Crypto

  module_function

  # 17. CBC padding attack

  def map_bytes(oracle, encrypter, encrypted, chunk)
    garbage = rand_text(16)
    (0..255).select do |e|
      text = to_text(xor(rand_block([e] + chunk), encrypter) + encrypted)
      oracle.decrypt(garbage, garbage + text)
    end
  end

  def find_byte(oracle, encrypter, encrypted, plain, step)
    chunk = xor(plain, [step] * plain.length)
    loop do
      candidates = map_bytes(oracle, encrypter, encrypted, chunk)
      break candidates.first if candidates.length == 1
    end
  end

  def crack_block(oracle, encrypter, encrypted)
    (1..16).each_with_object([]) do |i, plain|
      plain.insert(0, find_byte(oracle, encrypter, encrypted, plain, i) ^ i)
    end
  end

  def crack_cbc_by_padding(oracle)
    blocks = to_blocks(oracle.encrypt.join)
    Array.new(blocks.length - 1) do |pos|
      crack_block(oracle, blocks[pos], blocks[pos + 1])
    end
  end

  def cbc_padding_attack(filename)
    texts = File.read(filename).each_line.map { |e| Base64.decode64(e) }
    to_text(crack_cbc_by_padding(Oracle::PaddingChecker.new(texts)))
  end

  # 18. Manually implement CTR mode: the RECOMMANDED block encrytion mode

  def aes_ctr_decrypt(text, key_text, nonce_text, endianness = 'Q>')
    # the same method can be used to encrypt or decrypt
    # our OpenSSL lib packs counter into: uint64 big endian strings 'Q>'
    blocks = to_blocks(text)
    decrypted = blocks.map.with_index do |block, i|
      offset_text = nonce_text + [i].pack(endianness)
      intermediate = aes_encrypt(:ECB, offset_text, key_text, check: false)
      xor(block, intermediate.bytes[0...block.length])
    end
    to_text(decrypted)
  end

  def decrypt_ctr_mode(encoded_text, key_text, nonce_text)
    aes_ctr_decrypt(Base64.decode64(encoded_text), key_text, nonce_text, 'Q')
  end

  # 19. CTR mode fixed nonce attack

  def crack_ctr_by_substitution(oracle)
    sample = oracle.encrypt.map(&:bytes)
    key = transpose(sample).map { |e| break_xor(e)[1] }
    sample.map { |e| to_text(xor(e, key[0...e.length])) }
  end

  def ctr_substitution_attack(filename)
    texts = File.read(filename).each_line.map { |e| Base64.decode64(e) }
    crack_ctr_by_substitution(Oracle::SharedNonce.new(texts))
  end

  # 20. CTR mode fixed nonce attack, repeating key XOR method

  def ctr_repeating_xor_attack(filename)
    texts = File.read(filename).each_line.map { |e| Base64.decode64(e) }
    sample = Oracle::SharedNonce.new(texts).encrypt.map(&:bytes)
    break_one_time_pad(sample).map { |e| to_text(e) }
  end

  # 21. Implement MT19937: Mersenne Twister pseudorandom number generator

  def mt19937_rand(seed, nb_elements)
    r = Impl::MT19937.new(seed)
    Array.new(nb_elements) { r.rand }
  end

  # 22. Find MT19937 seed

  def guess_mt19937_seed
    time_seed = Time.now.to_i
    r = Impl::MT19937.new(time_seed)
    sleep rand_i(2..5)
    time_seed == time_based_seed(r.class, Array.new(10) { r.rand })
  end

  # 23. Clone MT19937 generator

  def used_random_generator
    r = Impl::MT19937.new(Time.now.to_i)
    rand_i(10_000).times { r.rand }
    r
  end

  def clone_mt19937
    r = used_random_generator
    r_clone = Impl::MT19937Clone.new(Array.new(2 * 624 + 10) { r.rand })
    Array.new(10) { r.rand == r_clone.rand }.all?
  end

  # 24. Create and crack a MT19937 based stream cipher

  def mt19937_encrypt_decrypt(filename)
    text = File.read(filename)
    key = rand_i(2**16)
    prng_class = Impl::MT19937
    text == prng_decrypt(prng_class, prng_encrypt(prng_class, text, key), key)
  end

  def find_seed(text)
    test_text = "\x00" * (text.bytes.length - 14) + 'A' * 14
    (0...2**16).each do |seed|
      encrypted_text = prng_encrypt(Impl::MT19937, test_text, seed)
      break seed if encrypted_text.bytes[-14..-1] == text.bytes[-14..-1]
    end
  end

  def crack_mt19937_cipher
    oracle = Oracle::PRNGPrependText.new(Impl::MT19937)
    find_seed(oracle.encrypt('A' * 14)) == oracle.key
  end

  def detect_mt19937_token
    prng_class = Impl::MT19937
    reset_token = token(prng_class)
    !time_based_seed(prng_class, Base64.decode64(reset_token).unpack('L')).nil?
  end
end
