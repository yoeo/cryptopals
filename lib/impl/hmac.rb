require_relative 'common'

module Impl
  # Implement Keyed hash message authentication code algorithm, HMAC
  class HMAC < CryptoHashBase
    def fragments(crypto_hash, key_text)
      key = key_text.bytes
      key = crypto_hash.digest(key_text) if key.length > 64
      key += [0] * (64 - key.length) if key.length < 64

      [0x5C, 0x36].map { |x| key.map { |y| x ^ y }.pack('C*') }
    end

    def digest(crypto_hash, key_text, text)
      o_key_pad, i_key_pad = fragments(crypto_hash, key_text)
      crypto_hash.digest(o_key_pad + crypto_hash.digest(i_key_pad + text))
    end
  end
end
