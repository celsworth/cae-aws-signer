# vim: et sw=2 ts=2 sts=2

$:.unshift(File.expand_path("../lib", File.dirname(__FILE__)))

require "rubygems"

gem 'minitest'
require "minitest/autorun"

require 'cae/aws/signer'

def refute_changes(what)
  old = what.call
  yield
  assert_equal old, what.call
end

