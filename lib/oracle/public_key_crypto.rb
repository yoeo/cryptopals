require 'json'
require 'openssl'

require_relative 'common'

module Oracle
  # Diffie-Hellman key exchange
  class Echo < Base
    def initialize(dh_class)
      @dh_class = dh_class
      @dh = nil
      @key_text = nil
      @message = nil
    end

    def state_machine
      %w(arguments public_key message response authenticate)
    end

    def step(args = nil)
      step_i, step_args = args || [0, []]
      [step_i + 1, send(state_machine[step_i], *step_args)]
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

  # Base class for man in the middle attacks
  class ManInTheMiddle
    def respond_to_missing?(method_name, include_private = false)
      state_machine.include?(method_name.to_s) || super
    end

    def method_missing(method_name, *args)
      if state_machine.include? method_name.to_s
        args # relay
      else
        super
      end
    end

    def step(args = nil)
      step_i, step_args = args || [0, []]
      [step_i, send(state_machine[step_i], *step_args)]
    end
  end

  # Inject parameters durring Diffie-Hellman key exchange
  class EchoManInTheMiddle < ManInTheMiddle
    def state_machine
      %w(arguments public_key message response authenticate)
    end

    def public_key(p, g, _remote_public_key)
      [p, g, @p = p]
    end

    def message(_remote_public_key)
      [@p]
    end
  end

  # Diffie-Hellman negociated group key exchange
  class EchoNG < Echo
    def state_machine
      %w(parameters ack public_key_a public_key_b message response authenticate)
    end

    def parameters
      @dh = @dh_class.new
      [@dh.p, @dh.g]
    end

    def ack(p, g)
      @dh = @dh_class.new(p, g)
      ['ACK']
    end

    def public_key_a(ack_message)
      raise 'ack failed' unless ack_message == 'ACK'
      [@dh.public_key]
    end

    def public_key_b(remote_public_key)
      session_key = @dh.compute_key(remote_public_key).to_s
      @key_text = OpenSSL::Digest::SHA1.digest(session_key)[0...16]
      [@dh.public_key]
    end

    def right_session_key?(session_key)
      @key_text == OpenSSL::Digest::SHA1.digest(session_key.to_s)[0...16]
    end
  end

  # Inject parameters durring Diffie-Hellman negociated group key exchange
  class EchoNGManInTheMiddle < ManInTheMiddle
    def initialize(g)
      @g = g
    end

    def state_machine
      %w(parameters ack public_key_a public_key_b message response authenticate)
    end

    def ack(p, _g)
      [p, @g]
    end
  end

  # Base RSA class
  class BaseRSA
    def initialize(rsa_class, key_size = 1024)
      @rsa = rsa_class.new(key_size)
    end

    def public_key
      @rsa.public_key
    end

    def encrypt(text)
      @rsa.encrypt(text)
    end

    private

    def decrypt(text)
      @rsa.decrypt(text)
    end
  end

  # Encrypts and decrypts a message only once
  class DecryptOnce < BaseRSA
    def initialize(rsa_class)
      super(rsa_class)
      @processed = []
    end

    def known?(text)
      text_hash = OpenSSL::Digest::SHA1.digest(text)
      return true if @processed.include? text_hash
      @processed << text_hash
      false
    end

    def encrypt(text)
      dump = JSON.dump(time: Time.now.to_i, social: text)
      encrypted_text = super(dump)
      known? encrypted_text
      encrypted_text
    end

    def decrypt(text)
      return if known? text
      super(text)
    end
  end

  # Checks that the decrypted message is even
  class ParityChecker < BaseRSA
    def even?(text)
      Impl::RSA.to_value(@rsa.decrypt(text)).even?
    end
  end

  # RSA messages signing
  class RSASigning < BaseRSA
    def sign(text)
      text_hash = Digest::SHA256.hexdigest(text)
      signature_text = "SHA256(f)= #{text_hash}"
      @rsa.decrypt(signature_text) # adds padding
    end

    def valid?(signature_blob, text)
      signature_text = @rsa.encrypt(signature_blob) # removes padding
      signature_hash = signature_text.split[1]
      signature_hash == Digest::SHA256.hexdigest(text)
    end
  end
end
