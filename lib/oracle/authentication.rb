require 'net/http'
require 'openssl'

require_relative 'common'

module Oracle
  # Generate / check keyed MAC for a message
  class MACCheck < Parser
    def initialize
      super(';=')
    end

    def authenticate(userdata)
      userdata.gsub!(/[#{@separators}]/, '')
      text =
        "comment1=cooking%20MCs;userdata=#{userdata};" \
        'comment2=%20like%20a%20pound%20of%20bacon'
      [text, mac(@key_text + text)]
    end

    def admin?(text, mac_text)
      raise 'authentication failed' unless mac(@key_text + text) == mac_text
      parse(text)['admin'] == 'true'
    end

    protected

    def mac(_text)
      raise NotImplementedError
    end
  end

  # Generate / check SHA-1 keyed MAC for a message
  class MACCheckSHA1 < MACCheck
    protected

    def mac(text)
      OpenSSL::Digest::SHA1.hexdigest(text)
    end
  end

  # Generate / check keyed MD4 MAC for a message
  class MACCheckMD4 < MACCheck
    protected

    def mac(text)
      OpenSSL::Digest::MD4.hexdigest(text)
    end
  end

  # Web server wrapper
  class WebServer
    def initialize(name, *args)
      command = "ruby #{server_path}/#{name}.rb #{args.join(' ')}"
      @base_uri = 'http://localhost:4567'
      @pid = Process.spawn(command, [:out, :err] => '/dev/null')
      sleep 3 # starting...
      yield self if block_given?
    ensure
      stop
    end

    def status_code(uri_string)
      Net::HTTP.get_response(URI("#{@base_uri}/#{uri_string}")).code.to_i
    end

    def server_path
      "#{File.dirname(__FILE__)}/../web_servers"
    end

    def stop
      Process.kill('TERM', @pid)
      Process.wait @pid
    end
  end
end
