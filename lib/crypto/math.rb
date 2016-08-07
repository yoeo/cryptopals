require 'bigdecimal'

require 'openssl'

# Cryptanalysis helper: math for big numbers
module Crypto
  module_function

  def mod_exp(base, exponent, modulo)
    base.to_bn.mod_exp(exponent, modulo)
  end

  def cubic_root(value)
    (BigDecimal.new(value)**Rational(1, 3)).round
  end
end
