require 'base64'
require 'openssl'

# Cryptanalysis helper: encryption methods
module Crypto
  module_function

  def ecb_mode?(blocks)
    blocks.length > blocks.uniq.length
  end

  def add_padding(text, size: 16)
    nb_missing = size - (text.bytes.length % size)
    nb_missing = 16 if nb_missing.zero?
    text + nb_missing.chr * nb_missing
  end

  def valid_padding?(text)
    last_byte = text.bytes[-1]
    return false if last_byte.zero?
    chunk = text.bytes[-last_byte..-1]
    !chunk.nil? && chunk.uniq.length == 1 && chunk[0] == last_byte
  end

  def del_padding(text)
    raise 'bad padding' unless valid_padding?(text)
    last_byte = text.bytes[-1]
    to_text(text.bytes[0...-last_byte])
  end

  def aes_do(action, mode, *options)
    text, key_text, iv_text, check = options
    raise 'unsuported mode' unless [:ECB, :CBC, :CTR].include? mode
    cipher = OpenSSL::Cipher::AES.new(128, mode)
    cipher.send(action)
    cipher.key = key_text
    cipher.padding = 0 unless check
    cipher.iv = iv_text unless iv_text.nil?
    cipher.update(text) + cipher.final
  end

  def aes_encrypt(mode, text, key_text, iv_text = nil, check: true)
    aes_do('encrypt', mode, text, key_text, iv_text, check)
  end

  def aes_decrypt(mode, text, key_text, iv_text = nil, check: true)
    aes_do('decrypt', mode, text, key_text, iv_text, check)
  end

  def bitflip(encrypted_text, pos, mask_chr, insert_text)
    blocks = to_blocks(encrypted_text)
    target = blocks[pos]
    size = insert_text.bytes.length
    target[-size..-1] = xor(
      target[-size..-1], (mask_chr * size).bytes, insert_text.bytes
    )
    to_text(blocks)
  end

  def time_based_seed(prng_class, numbers)
    now = Time.now.to_i
    now.downto(now - 3600) do |seed|
      r = prng_class.new(seed)
      return seed if numbers == Array.new(numbers.length) { r.rand }
    end
    nil
  end

  def prng_encrypt(prng_class, text, key)
    r = prng_class.new(key)
    to_text(text.bytes.map { |e| e ^ r.rand & 0xFF })
  end

  alias prng_decrypt prng_encrypt

  def token(prng_class)
    Base64.encode64([prng_class.new(Time.now.to_i).rand].pack('L'))
  end
end
