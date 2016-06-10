require_relative '../crypto'

# Oracles that produces encrypted text
module Oracle
  # Base encryption Oracle
  class Base
    include Crypto

    def initialize
      @key_text = rand_text(16)
    end

    def encrypt(_text)
      raise NotImplementedError
    end
  end

  # Appends a secret text an encrypts messages in ECB mode
  class AppendText < Base
    def initialize(secret_text)
      @secret_text = secret_text
      super()
    end

    def encrypt(text)
      aes_encrypt(:ECB, text + @secret_text, @key_text)
    end
  end

  # Encoded data parser
  class Parser < Base
    def initialize(separators)
      @separators = separators
      super()
    end

    protected

    def parse(encoded_text)
      first, second = @separators.chars
      encoded_text.split(first).map { |e| e.split(second) }.to_h
    end
  end
end

require_relative 'common'

module Oracle
end
