require 'digest'
require 'json'

require_relative 'impl'
require_relative 'oracle'

# Attacking RSA and DSA cryptosystems
# see http://cryptopals.com/sets/6/
module RSAAndDSA
  extend Crypto

  module_function

  # 41. Patch RSA unpadded encrypted data, to recover the original plaintext

  def patch(text, public_key)
    value = Impl::RSA.to_value(text)
    e_value, n_prime = public_key
    s_random = rand_i(1..n_prime.to_i)
    result = mod_exp(s_random, e_value, n_prime) * value % n_prime
    [Impl::RSA.to_text(result), s_random]
  end

  def unpatch(text, s_random, public_key)
    value = Impl::RSA.to_value(text)
    n_prime = public_key[1]
    source_value = value * Impl::Modulo.invmod(s_random, n_prime) % n_prime
    Impl::RSA.to_text(source_value)
  end

  def recover_unpadded(text)
    oracle = Oracle::UnpaddedRSA.new(Impl::RSA)
    encrypted = oracle.encrypt(text)

    patched_encrypted, s_random = patch(encrypted, oracle.public_key)
    patched_decrypted = oracle.decrypt(patched_encrypted)
    unpached_decrypted = unpatch(patched_decrypted, s_random, oracle.public_key)

    JSON.load(unpached_decrypted)['social']
  end

  # 42. Fake RSA signature

  def signature_content(text_hash, nb_chars)
    signature_text = "\x00\x01\xFF\x00SHA256(f)= #{text_hash}\n"
    signature_text += "\x00" * (nb_chars - signature_text.bytes.length)
    signature_text.force_encoding('ASCII-8BIT')
  end

  def forge_signature(text, public_key)
    e_value, n_prime = public_key
    raise 'work only for E=3 RSA public key' unless e_value == 3

    text_hash = Digest::SHA256.hexdigest(text)
    signature_text = signature_content(text_hash, n_prime.to_i.bit_length / 8)
    Impl::RSA.to_text(cubic_root(Impl::RSA.to_value(signature_text)))
  end

  def valid_pkcs1(signature_text, text)
    signature_text = "\x00" + signature_text unless signature_text[0] == "\x00"
    re = "\x00\x01[\xFF]+\x00([^\n]+)".force_encoding('ASCII-8BIT')

    match = signature_text.match(re)
    return false unless match
    signature_hash = match.captures[0].split[1]
    text_hash = Digest::SHA256.hexdigest(text)

    signature_hash == text_hash
  end

  def valid_signature?(signature_blob, text, rsa)
    signature_text = rsa.encrypt(signature_blob).force_encoding('ASCII-8BIT')
    valid_pkcs1(signature_text, text)
  end

  def fake_signature(text)
    rsa = Impl::RSA.new
    rsa.drop_private!

    signature_blob = forge_signature(text, rsa.public_key)
    valid_signature?(signature_blob, text, rsa)
  end

  # 43. Recover DSA private key from insecure session key

  def dsa_signing(message_signing, message_validation)
    dsa = Impl::DSA.new
    dsa.validate(message_validation, *dsa.sign(message_signing))
  end

  def make_public_key(x)
    Impl::DSA::G.to_bn.mod_exp(x, Impl::DSA::P).to_i
  end

  def recover_private_key(message, r, s, y)
    h = Digest::SHA1.hexdigest(message).to_i(16)
    q = Impl::DSA::Q
    (2**16).times do |k|
      x = Impl::Modulo.invmod(r, q) * (s * k - h) % q
      return x if make_public_key(x) == y
    end
  end

  def dsa_key_recovered(message, r, s, y)
    Digest::SHA1.hexdigest(recover_private_key(message, r, s, y).to_s(16))
  end
end
