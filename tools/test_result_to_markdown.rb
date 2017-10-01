#!/usr/bin/env ruby

SET_INDICATOR = 'lib/set_'
EXT_INDICATOR = '.rb'

TITLE = '[%{printname}](%{filename})'
REGEX_LIST = [
  [/^(\w+)/, '@\1'],
  [/^\s+(\d+\..+)/, '  - [x] **\1**'],
  [/^\s+(\w+)/, '    - \1'],
]
REPLACED_TITLE_RE = /^@(.+)/
UNCHANGED = ['and']

def link(filename)
  start = SET_INDICATOR.length
  finish = -1 - EXT_INDICATOR.length
  name = filename[start..finish].gsub('_', ' ')
  printname = name.split.map.with_index do |e, idx|
    if idx.zero?
      "#{e}."
    else
      if UNCHANGED.include?(e) then e else e.capitalize end
    end
  end.join(' ')
  name.gsub!(' ', '').gsub!(/^\d+/, '')
  [name, TITLE % { :printname => printname, :filename => filename }]
end

def main(lines)
  REGEX_LIST.map { |e| lines.gsub!(e[0], e[1]) }
  titles = Hash[Dir.glob("#{SET_INDICATOR}*").map { |e| link(e) }]
  lines.gsub!(REPLACED_TITLE_RE) { |e| titles[e.downcase[1..-1]] }
end

puts main(ARGF.read)
