require_relative 'crypto'
require_relative 'oracle'
require_relative 'impl'

# Attacking stream crypto and introducing message authentication
# see http://cryptopals.com/sets/4/
module StreamCryptoAndRandomness
  extend Crypto

  module_function

  # 25. Crack CTR cipher with a read/write oracle. Eg: files encryption

  def ctr_random_access_attack(filename, key_text)
    ebc_encrypted_text = Base64.decode64(File.read(filename))
    oracle = Oracle::RandomAccess.new(
      aes_decrypt(:ECB, ebc_encrypted_text, key_text)
    )

    encrypted = oracle.edit.bytes
    keystream = oracle.edit("\x00" * encrypted.length, 0).bytes
    to_text(xor(encrypted, keystream))
  end

  # 26. Apply bit flipping attack to CTR encrypted data

  def bitflip_ctr_encrypted_data
    oracle = Oracle::ProfileComment.new(';=', :CTR)
    oracle.decrypt(bitflip(oracle.encrypt('A' * 32), 3, 'A', ';admin=true'))
  end

  # 27. Recover CBC key when the key is used as the IV

  def crack_cbc_iv(oracle, text)
    blocks = to_blocks(text)
    blocks.insert(0, blocks[0].dup, [0] * 16)
    begin
      oracle.decrypt(to_text(blocks))
    rescue RuntimeError => e
      plain = to_blocks(e.to_s.gsub('Not an ASCII string: ', ''))
    end
    to_text(xor(plain[0], plain[2]))
  end

  def recover_cbc_key(secret_text)
    oracle = Oracle::AsciiProfileComment.new(';=', secret_text)
    text = oracle.encrypt
    iv_text = crack_cbc_iv(oracle, text)
    aes_decrypt(:CBC, text, iv_text, iv_text.dup)
  end

  # 28. Generate a SHA-1 MAC, associating message and key

  def sha1_mac(key_text, text)
    Impl::SHA1.hexdigest(key_text + text)
  end

  # 29. Break MAC implemented as Hash(key + message), with SHA-1 hash

  def break_keyed_mac(text, mac_text, extensible_hash_class)
    crypto_hash = extensible_hash_class.new(text.length + 16, mac_text)

    added_text = ';admin=true'
    tempered_text = text + to_text(crypto_hash.previous_padding) + added_text
    tempered_mac_text = to_hex(crypto_hash.digest(added_text).bytes)
    [tempered_text, tempered_mac_text]
  end

  def break_sha1_mac
    oracle = Oracle::MACCheckSHA1.new
    text, mac_text = oracle.authenticate('AAA')
    oracle.admin?(*break_keyed_mac(text, mac_text, Impl::ExtensibleSHA1))
  end

  # 30. Break MAC implemented as Hash(key + message), with MD4 hash

  def md4_mac(key_text, text)
    Impl::MD4.hexdigest(key_text + text)
  end

  def break_md4_mac
    oracle = Oracle::MACCheckMD4.new
    text, mac_text = oracle.authenticate('AAA')
    oracle.admin?(*break_keyed_mac(text, mac_text, Impl::ExtensibleMD4))
  end

  # 31. Implement HMAC-SHA1 containing an artificial timing leak

  def sha1_hmac(key_text, text)
    Impl::HMAC.hexdigest(Impl::SHA1.new, key_text, text)
  end

  def check_hmac(oracle, filename, hmac)
    oracle.status_code("test?file=#{filename}&signature=#{hmac}")
  end

  def timing_min(nb_iter)
    Array.new(nb_iter) do
      before = Time.now
      yield
      Time.now - before
    end.min
  end

  def gen_signature(key_len: 20, nb_iter: 1)
    to_hex((0...key_len).reduce(Array.new(key_len, 0)) do |hmac, i|
      Array.new(256) do |byte|
        temp_hmac = hmac.dup
        temp_hmac[i] = byte
        [timing_min(nb_iter) { yield to_hex(temp_hmac) }, temp_hmac]
      end.max[1]
    end)
  end

  def get_code(oracle, filename, signature)
    oracle.status_code("test?file=#{filename}&signature=#{signature}")
  end

  def timed_sha1_hmac(filename, *oracle_args, **signature_args)
    Oracle::WebServer.new('slow_hmac', *oracle_args) do |oracle|
      signature = gen_signature(**signature_args) do |temp_signature|
        get_code(oracle, filename, temp_signature)
      end
      return get_code(oracle, filename, signature)
    end
  end

  def partial_timed_sha1_hmac(filename)
    timed_sha1_hmac(filename, 0.05, 1, key_len: 1)
  end

  def full_timed_sha1_hmac(filename)
    timed_sha1_hmac(filename, 0.05)
  end

  # 32. Implement HMAC-SHA1 containing an artificial micro timing leak

  def partial_milli_timed_sha1_hmac(filename)
    timed_sha1_hmac(filename, 0.005, 1, nb_iter: 20, key_len: 1)
  end

  def full_milli_timed_sha1_hmac(filename)
    timed_sha1_hmac(filename, 0.005, nb_iter: 20)
  end
end
