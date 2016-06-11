require 'securerandom'

# Cryptanalysis helper: value converters and generators
module Crypto
  module_function

  def to_text(bytes)
    bytes.flatten.pack('C*')
  end

  def to_hex(bytes)
    bytes.pack('C*').unpack('H*').first
  end

  def to_blocks(text)
    text.bytes.each_slice(16).to_a
  end

  def rand_text(length)
    SecureRandom.random_bytes(length)
  end

  def rand_i(value)
    if value.instance_of?(Range) # for ruby < 2.3 compatibility
      value.first + SecureRandom.random_number(value.size)
    else
      SecureRandom.random_number(value)
    end
  end

  def rand_block(chunk = [])
    rand_text(16 - chunk.length).bytes + chunk
  end

  def to_iv(nonce_text, counter)
    nonce_text + [counter].pack('Q>')
  end
end
