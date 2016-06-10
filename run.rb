#!/usr/bin/env ruby

require 'optparse'

filters = '-t ~slow'
OptionParser.new do |opts|
  opts.banner += ' [SET_NUMBER]'
  opts.separator 'Tests the implementation of Cryptopals Crypto Challenges.'
  opts.on('--slow', 'run slow tests, may take hours') { filters = '' }
end.parse!
test_set = ARGV.empty? ? '' : "test_set_#{ARGV[0]}"

exit system("rspec -fd #{filters} spec/#{test_set}*")
