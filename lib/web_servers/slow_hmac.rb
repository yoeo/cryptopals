require 'openssl'
require 'securerandom'
require 'sinatra'
require 'uri'

WAIT_TIME = (ARGV[0] || 0.05).to_f
MIN_KEY_SIZE = (ARGV[1] || 1_000_000).to_i
SECRET_KEY = SecureRandom.random_bytes(16)

def insecure_compare(real_hash, given_hash)
  real_hash.each_with_index do |e, i|
    break unless i < MIN_KEY_SIZE
    return false unless e == given_hash[i]
    sleep WAIT_TIME
  end
  true
end

get '/test' do
  params = URI.decode_www_form(request.query_string).to_h
  raise 'missing params' unless %w(file signature).all? { |e| params.key?(e) }

  real_hash = OpenSSL::HMAC.digest(
    OpenSSL::Digest::SHA1.new, SECRET_KEY, params['file']
  ).bytes
  given_hash = [params['signature']].pack('H*').bytes
  [insecure_compare(real_hash, given_hash) ? 200 : 500, {}, '']
end
