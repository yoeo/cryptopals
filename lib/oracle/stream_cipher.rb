require_relative 'common'

module Oracle
  # CTR encryption with same nonce
  class SharedNonce < Base
    def initialize(secret_texts)
      @secret_texts = secret_texts
      @nonce_text = "\0" * 16
      super()
    end

    def encrypt
      @secret_texts.map { |e| aes_encrypt(:CTR, e, @key_text, @nonce_text) }
    end
  end

  # PRNG stream cipher, prepend random data to the plain message
  class PRNGPrependText
    include Crypto
    attr_reader :key

    def initialize(prng_class)
      @key = rand_i(2**16)
      @prng_class = prng_class
    end

    def encrypt(text)
      garbage_text = rand_text(rand_i(10..100))
      prng_encrypt(@prng_class, garbage_text + text, key)
    end
  end

  # Encrypts in CTR mode with random access
  class RandomAccess < Base
    def initialize(secret_text)
      super()
      @nonce_text = rand_text(8)
      @encrypted = encrypt(secret_text).bytes
    end

    def edit(new_text = nil, offset = 0)
      return to_text(@encrypted) if new_text.nil?
      modified = encrypt(new_text, offset).bytes
      stop = offset + modified.length
      to_text(@encrypted[0...offset] + modified + @encrypted[stop..-1])
    end

    private

    def encrypt(text, counter = 0)
      aes_encrypt(:CTR, text, @key_text, to_iv(@nonce_text, counter))
    end
  end
end
