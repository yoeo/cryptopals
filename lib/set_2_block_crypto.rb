require 'base64'

require_relative 'crypto'
require_relative 'oracle'

# Set of block ciphers crypto tests
# see http://cryptopals.com/sets/2/
module BlockCrypto
  extend Crypto

  module_function # all functions are accessible everywhere

  # 9. Append PKCS#7 padding to input blocks

  def append_pkcs_7_padding(text, block_size)
    add_padding(text, size: block_size)
  end

  # 10. Decrypt AES-CBC messages using AES-ECB

  def manually_decrypt_cbc(filename, key_text, iv_text)
    text = Base64.decode64(File.read(filename))
    decrypted = aes_decrypt(:ECB, text, key_text, check: false).bytes
    unscrambler = (iv_text.bytes + text.bytes)[0...text.bytes.length]
    to_text(xor(decrypted, unscrambler))
  end

  # 11. Detect ECB ot CBC mode

  def guess_encryption_mode
    oracle = Oracle::RandomCypher.new
    oracle.is_ecb == ecb_mode?(to_blocks(oracle.encrypt('A' * 3 * 16)))
  end

  # 12. Crack ECB, simple version

  def retrieve_blocks(oracle, key_block, forged_text)
    loop do
      blocks = to_blocks(oracle.encrypt(forged_text))
      position = blocks.index(key_block)
      break blocks[position..-1] unless position.nil?
    end
  end

  def make_sample(oracle, key_block, padded_text)
    Array.new(256) do |c|
      retrieve_blocks(oracle, key_block, padded_text + c.chr)
    end
  end

  def score_sample(sample, reference_blocks)
    sample.map do |blocks|
      reference_blocks.each_with_index.map do |block, i|
        block == blocks[i] ? 1 : 0
      end.reduce(:+)
    end
  end

  def find_char(oracle, key_block, padding, text)
    reference_blocks = retrieve_blocks(oracle, key_block, padding)
    sample = make_sample(oracle, key_block, padding + text)
    scores = score_sample(sample, reference_blocks)
    scores.count(scores.max) != 1 ? nil : scores.index(scores.max).chr
  end

  def feed(text, nb_bytes: 1_000)
    15.downto(0).cycle do |i|
      padding = 'K' * 16 + 'A' * i
      return text if (c = yield padding, text).nil? || nb_bytes < 16 - i
      text << c
    end
  end

  def get_key_block(oracle)
    # 10 is a randomly piked number
    sample = Array.new(10).map { to_blocks(oracle.encrypt('K' * 2 * 16)) }
    sample[0].select do |block|
      sample.all? { |blocks| blocks.include? block }
    end[0]
  end

  def find_encrypted_text(oracle, **args)
    key_block = get_key_block(oracle)
    feed('', **args) do |padding, text|
      find_char(oracle, key_block, padding, text)
    end
  end

  def byte_by_byte_guess(unknown_text)
    # assume encryption mode is ECB and block_size is 16
    find_encrypted_text(Oracle::AppendText.new(Base64.decode64(unknown_text)))
  end

  # 13. Alter ECB encrypted message

  def cut_block(oracle)
    padded = add_padding('admin')
    cut_email = 'A' * (16 - 6) + padded # 6 == 'email='.length
    oracle.profile_for(cut_email).bytes[16...32]
  end

  def paste_block(oracle, block)
    paste_email = 'A' * (16 - (19 % 16)) # 19 == 'email=&uid=10&role='.length
    oracle.profile_for(paste_email).bytes[0...2 * 16] + block
  end

  def alter_ecb_encrypted_data
    oracle = Oracle::ProfileData.new('&=')
    oracle.decrypt(to_text(paste_block(oracle, cut_block(oracle))))
  end

  # 14. Crack ECB, complex version

  def random_byte_guess(unknown_text, **args)
    # assume encryption mode is ECB and block_size is 16
    find_encrypted_text(
      Oracle::RandomAppendText.new(Base64.decode64(unknown_text)), **args
    )
  end

  # 15. Validate and strip PKCS#7 padding

  def strip_pkcs_7_padding(text)
    del_padding(text)
  end

  # 16. Attack CBC by flipping bits

  def bitflip_cbc_encrypted_data
    oracle = Oracle::ProfileComment.new(';=')
    begin
      oracle.decrypt(bitflip(oracle.encrypt('A' * 32), 2, 'A', ';admin=true'))
    rescue ArgumentError # decrypted data parsing failed
      retry
    end
  end
end
