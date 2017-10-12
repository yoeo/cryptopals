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

  # 41. Patch RSA unpadded encrypted data, to recover the original plaintext

  def patch(text, public_key)
    value = Impl::RSA.to_value(text)
    e_value, n_modulus = public_key
    s_random = rand_i(1..n_modulus.to_i).to_bn
    result = s_random.mod_exp(e_value, n_modulus).mod_mul(value, n_modulus)
    [Impl::RSA.to_text(result), s_random.to_i]
  end

  def unpatch(text, s_random, public_key)
    value = Impl::RSA.to_value(text).to_bn
    n_modulus = public_key[1]
    result = value.mod_mul(s_random.to_bn.mod_inverse(n_modulus), n_modulus)
    Impl::RSA.to_text(result)
  end

  def recover_unpadded(text)
    oracle = Oracle::DecryptOnce.new(Impl::RSA)
    encrypted = oracle.encrypt(text)

    patched_encrypted, s_random = patch(encrypted, oracle.public_key)
    patched_decrypted = oracle.decrypt(patched_encrypted)
    decrypted = unpatch(patched_decrypted, s_random, oracle.public_key)

    JSON.load(decrypted)['social']
  end

  # 42. Fake RSA signature

  def signature_content(text_hash, nb_chars)
    signature_text = "\x00\x01\xFF\x00SHA256(f)= #{text_hash}\n"
    signature_text += "\x00" * (nb_chars - signature_text.bytes.length)
    signature_text.force_encoding('ASCII-8BIT')
  end

  def forge_signature(text, public_key)
    e_value, n_modulus = public_key
    raise 'work only for E=3 RSA public key' unless e_value == 3

    text_hash = Digest::SHA256.hexdigest(text)
    signature_text = signature_content(text_hash, n_modulus.bit_length / 8)
    Impl::RSA.to_text(cubic_root(Impl::RSA.to_value(signature_text)))
  end

  def legit_signature(text)
    oracle = Oracle::RSASigning.new(Impl::SignaturePaddedRSA)
    signature_blob = oracle.sign(text)
    oracle.valid?(signature_blob, text)
  end

  def fake_signature(text)
    oracle = Oracle::RSASigning.new(Impl::SignaturePaddedRSA)
    signature_blob = forge_signature(text, oracle.public_key)
    oracle.valid?(signature_blob, text)
  end

  # 43. Recover DSA private key from insecure session key

  def dsa_signing(message_signing, message_validation)
    dsa = Impl::DSA.new
    dsa.validate(message_validation, *dsa.sign(message_signing))
  end

  def make_public_key(x)
    Impl::DSA::G.to_bn.mod_exp(x, Impl::DSA::P).to_i
  end

  def make_private_key(h, k, r, s)
    r.to_bn.mod_inverse(Impl::DSA::Q).to_i * (s * k - h) % Impl::DSA::Q
  end

  def recover_private_key(message, r, s, y)
    h = Digest::SHA1.hexdigest(message).to_i(16)
    (2**16).times do |k|
      x = make_private_key(h, k, r, s)
      return x if make_public_key(x) == y
    end
  end

  def to_sha1(value)
    Digest::SHA1.hexdigest(value.to_s(16))
  end

  def dsa_key_recovered(message, r, s, y)
    to_sha1(recover_private_key(message, r, s, y))
  end

  # 44. Recover DSA private key from reused session key

  def read_signatures(filename)
    File.read(filename).each_line.each_slice(4).map do |lines|
      [10, 10, 16].each_with_index.map do |base, index|
        lines[index + 1][3..-1].to_i(base)
      end.to_a
    end
  end

  def compute_keys(first_signature, second_signature)
    s_one, r, m_one = *first_signature
    s_two, _, m_two = *second_signature
    q = Impl::DSA::Q
    k = (s_one - s_two).to_bn.mod_inverse(q).mod_mul(m_one - m_two, q)
    x = make_private_key(m_one, k, r, s_one)
    [x, make_public_key(x)]
  end

  def reused_key_recovery(filename)
    data = read_signatures(filename)
    r_values = data.map { |e| e[1] }
    r = r_values.select { |e| r_values.count(e) > 1 }[0]
    signatures = data.select { |e| e[1] == r }[0..2]
    x, y = compute_keys(*signatures)
    [to_sha1(x), y]
  end
end
