require 'base64'
require 'digest'
require 'json'
require 'openssl'
require 'timeout'

require_relative 'crypto'
require_relative 'impl'
require_relative 'oracle'

# Attacking RSA and DSA cryptosystems
# see http://cryptopals.com/sets/6/
module RSAAndDSA
  extend Crypto

  module_function

  # 45. Force DSA parameters

  def force_params(messages, **params)
    dsa = Impl::DSA.new(**params)
    signature = Timeout.timeout(2) do
      dsa.sign('a random message')
    end
    messages.all? { |e| dsa.validate(e, *signature) }
  rescue Timeout::Error
    'Timeout'
  end

  # 46. RSA crack from parity check

  def result_even?(oracle, encrypted, index, value = 0)
    multiplier = (value + (1 << index)).to_bn.mod_exp(*oracle.public_key)
    computed = multiplier.mod_mul(encrypted, oracle.public_key[1])
    oracle.even?(Impl::RSA.to_text(computed))
  end

  def smallest_multiplier(oracle, encrypted)
    n_modulus_bit_length = oracle.public_key[1].bit_length
    top_index = (1...n_modulus_bit_length).each do |e|
      break e unless result_even?(oracle, encrypted, e + 1)
    end
    top_index.downto(1).reduce(0) do |a, e|
      result_even?(oracle, encrypted, e, a) ? a + (1 << e) : a
    end
  end

  def border_control(oracle, encrypted)
    # the math:
    #   exists s E ]0, n[ : m*s <= n <= m*(s + 1)
    #   -> m <= n/s <= m + 1/s
    #   -> n/s E [m, m + 1/s] : 1/s <= 1
    #   -> floor(n/s) = m
    n_modulus = oracle.public_key[1]
    s_multiplier = smallest_multiplier(oracle, encrypted)
    Impl::RSA.to_text(n_modulus.to_i / s_multiplier)
  end

  def parity_crack(text)
    oracle = Oracle::ParityChecker.new(Impl::RSA)
    encrypted = Impl::RSA.to_value(oracle.encrypt(Base64.decode64(text)))
    border_control(oracle, encrypted)
  end

  # 47. RSA crack message from Bleichenbacher's PKCS#1 v1.5 hack, simple case

  def chosen_cyphertext_attack(text)
    oracle = Oracle::MessageCkecker.new(Impl::EncryptionPaddedRSA)
    encrypted = oracle.encrypt(text)
    oracle.valid?(encrypted)
  end
end
