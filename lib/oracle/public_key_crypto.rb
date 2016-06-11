require 'openssl'

require_relative 'common'

module Oracle
  # Diffie-Hellman key exchange
  class Echo < Base
    STATE_MACHINE =
      %w(arguments public_key message response authenticate).freeze

    attr_reader :authenticated

    def initialize
      @key_gen = nil
      @key_text = nil
      @message = nil
    end

    def step(args = nil)
      step_i, step_args = args || [0, []]
      puts "#{self}: #{step_i}/#{STATE_MACHINE[step_i]}: #{step_args}"
      [step_i + 1, send(STATE_MACHINE[step_i], *step_args)]
    end

    def encrypt
      iv_text = rand_text(16)
      [aes_encrypt(:CBC, @message, @key_text, iv_text), iv_text]
    end

    def decrypt(text, iv_text)
      aes_decrypt(:CBC, text, @key_text, iv_text)
    end

    # state machine steps

    def arguments
      @key_gen = OpenSSL::PKey::DH.new(1024)
      [@key_gen.public_key.to_der, @key_gen.pub_key]
    end

    def public_key(der, remote_pub_key)
      @key_gen = OpenSSL::PKey::DH.new(der)
      @key_gen.generate_key!
      session_key = @key_gen.compute_key(remote_pub_key)
      @key_text = OpenSSL::Digest::SHA1.digest(session_key)[0...16]
      [@key_gen.pub_key]
    end

    def message(remote_pub_key)
      session_key = @key_gen.compute_key(remote_pub_key)
      @key_text = OpenSSL::Digest::SHA1.digest(session_key)[0...16]
      @message = %w(lama rat dolphin)[rand_i(3)]
      encrypt
    end

    def response(encrypted_text, iv_text)
      @message = "I'm a #{decrypt(encrypted_text, iv_text)}"
      encrypt
    end

    def authenticate(encrypted_text, iv_text)
      decrypt(encrypted_text, iv_text) == "I'm a #{@message}"
    end
  end

  # Inject parameters durring Diffie-Hellman key exchange
  class EchoInjecter < Echo
  end
end
