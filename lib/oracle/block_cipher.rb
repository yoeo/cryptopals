require_relative 'common'

module Oracle
  # Randomly encrypts messages in ECB or CBC mode
  class RandomCypher < Base
    attr_reader :is_ecb

    def initialize
      @is_ecb = rand_i(2).zero?
      super()
    end

    def encrypt(text)
      mode, iv_text = @is_ecb ? [:ECB, nil] : [:CBC, rand_text(16)]
      full_text = rand_text(rand_i(5..10)) + text + rand_text(rand_i(5..10))
      aes_encrypt(mode, full_text, @key_text, iv_text)
    end
  end

  # Profile data ECB encrypter
  class ProfileData < Parser
    def encrypt(email)
      email.gsub!(/[#{@separators}]/, '')
      encoded_text = "email=#{email}&uid=10&role=user"
      aes_encrypt(:ECB, encoded_text, @key_text)
    end

    alias profile_for encrypt

    def decrypt(encrypted_text)
      parse(aes_decrypt(:ECB, encrypted_text, @key_text))
    end
  end

  # Appends a secret text, prepend garbage then encrypts in ECB mode
  class RandomAppendText < AppendText
    def encrypt(text)
      super(rand_text(rand_i(255)) + text)
    end
  end

  # Adds comments to user data and encrypts it in CBC mode
  class ProfileComment < Parser
    def initialize(separators, mode = :CBC)
      @iv_text = Crypto.rand_text(16)
      @mode = mode
      super(separators)
    end

    def encrypt(userdata)
      userdata.gsub!(/[#{@separators}]/, '')
      encoded_text =
        "comment1=cooking%20MCs;userdata=#{userdata};" \
        'comment2=%20like%20a%20pound%20of%20bacon'
      aes_encrypt(@mode, encoded_text, @key_text, @iv_text)
    end

    def decrypt(encrypted_text)
      decrypted_text = aes_decrypt(@mode, encrypted_text, @key_text, @iv_text)
      parse(decrypted_text)['admin'] == 'true'
    end
  end

  # Checks padding of CBC encrypted data
  class PaddingChecker < Base
    def initialize(secret_texts)
      @secret_texts = secret_texts
      super()
    end

    def encrypt
      iv_text = Crypto.rand_text(16)
      [iv_text, aes_encrypt(:CBC, @secret_texts.sample, @key_text, iv_text)]
    end

    def decrypt(iv_text, encrypted_text)
      valid_padding?(
        aes_decrypt(:CBC, encrypted_text, @key_text, iv_text, check: false)
      )
    end
  end

  # Check the decrypted url for non ASCII chars
  class AsciiProfileComment < ProfileComment
    def initialize(separators, secret_text)
      super(separators, :CBC)
      @iv_text = @key_text.dup # copy the key, use it as the IV
      @secret_text = secret_text
    end

    def encrypt
      super(@secret_text)
    end

    def decrypt(encrypted_text)
      text = aes_decrypt(@mode, encrypted_text, @key_text, @iv_text)
      raise "Not an ASCII string: #{text}" unless text.ascii_only?
      parse(text)['admin'] == 'true'
    end
  end
end
