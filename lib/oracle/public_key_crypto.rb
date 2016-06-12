require 'openssl'

require_relative 'common'

module Oracle
  # Diffie-Hellman key exchange
  class Echo < Base
    STATE_MACHINE =
      %w(arguments public_key message response authenticate).freeze

    def initialize(dh_class)
      @dh_class = dh_class
      @dh = nil
      @key_text = nil
      @message = nil
    end

    def step(args = nil)
      step_i, step_args = args || [0, []]
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
      @dh = @dh_class.new
      [@dh.p, @dh.g, @dh.public_key]
    end

    def public_key(p, g, remote_public_key)
      @dh = @dh_class.new(p, g)
      session_key = @dh.compute_key(remote_public_key).to_s
      @key_text = OpenSSL::Digest::SHA1.digest(session_key)[0...16]
      [@dh.public_key]
    end

    def message(remote_public_key)
      session_key = @dh.compute_key(remote_public_key).to_s
      @key_text = OpenSSL::Digest::SHA1.digest(session_key)[0...16]
      @message = %w(lama panda dolphin)[rand_i(3)]
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
    def step(args = nil)
      step_i, result = super(args)
      [step_i - 1, result]
    end

    def relay(*args)
      args
    end

    alias arguments relay
    alias response relay
    alias authenticate relay

    def public_key(p, g, _remote_public_key)
      @p = p
      [p, g, p]
    end

    alias arguments relay

    def message(_remote_public_key)
      [@p]
    end
  end
end
