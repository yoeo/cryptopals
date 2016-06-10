require 'openssl'

require_relative 'common'

module Oracle
  # Diffie-Hellman key exchange
  class Echo < Base
    STATES = {
      put: [:put_arguments, :put_key, :put_message, :put_response],
      get: [:get_arguments, :get_key, :get_message, :get_response]
    }.freeze

    attr_reader :authenticated

    def initialize
      @key_gen = nil
      @remote_pub_key = 0
      @state_i = 0
      @message = %w(dog lama rat eagle frog lion lizad dolphin)[rand_i(8)]
      @authenticated = true
    end

    def encrypt
      iv_text = rand_text(16)
      session_key = @key_gen.compute_key(@remote_pub_key)
      key_text = OpenSSL::Digest::SHA1.digest(session_key)[0...16]
      [aes_encrypt(:CBC, @message, key_text, iv_text), iv_text]
    end

    def decrypt(text, iv_text)
      session_key = @key_gen.compute_key(@remote_pub_key)
      key_text = OpenSSL::Digest::SHA1.digest(session_key)[0...16]
      aes_decrypt(:CBC, text, key_text, iv_text)
    end

    # send data

    def put_arguments
      @key_gen = OpenSSL::PKey::DH.new(1024)
      [@key_gen.public_key.to_der, @key_gen.pub_key]
    end

    def put_key
      [@key_gen.pub_key]
    end

    alias put_message encrypt
    alias put_response encrypt

    def put
      puts "put #{self} => #{@state_i}"
      @state_i += 1
      send(STATES[:put][@state_i - 1])
    end

    # receive data

    def get_arguments(der, remote_pub_key)
      get_key(remote_pub_key)
      @key_gen = OpenSSL::PKey::DH.new(der)
      @key_gen.generate_key!
    end

    def get_key(remote_pub_key)
      @remote_pub_key = remote_pub_key
    end

    def get_message(encrypted_text, iv_text)
      @message = "I'm a #{decrypt(encrypted_text, iv_text)}"
    end

    def get_response(encrypted_text, iv_text)
      @authenticated = decrypt(encrypted_text, iv_text) == "I'm a #{@message}"
    end

    def get(args)
      puts "get #{self} => #{@state_i} | #{args.inspect}"
      send(STATES[:get][@state_i], *args)
      @state_i += 1
    end
  end

  # Inject parameters durring Diffie-Hellman key exchange
  class EchoInjecter < Echo
    attr_reader :forged

    # send data

    alias put_arguments forged
    alias put_key forged
    alias put_message forged
    alias put_response forged

    # receive data

    def get_arguments(der, _remote_pub_key)
      @key_gen = OpenSSL::PKey::DH.new(der)
      @forged = [der, @key_gen.p]
    end

    def get_key2(_remote_pub_key)
      @forged = [@key_gen.p]
    end

    def get_message(encrypted_text, iv_text)
      @forged = [encrypted_text, iv_text]
    end

    alias get_message get_response
  end
end
