require 'bigdecimal'

# Cryptanalysis helper: math for big numbers
module Crypto
  module_function

  def cubic_root(value)
    (BigDecimal.new(value)**Rational(1, 3)).round
  end
end
