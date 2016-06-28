# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'cae/aws/signer/version'

Gem::Specification.new do |spec|
	spec.name          = "cae-aws-signer"
	spec.version       = Cae::Aws::Signer::VERSION
	spec.authors       = ["Chris Elsworth"]
	spec.email         = ["chris@shagged.org"]
	spec.summary       = ""
	spec.homepage      = ""
	spec.license       = "MIT"

	spec.files         = `git ls-files -z`.split("\x0")
	spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
	spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
	spec.require_paths = ["lib"]

	spec.add_development_dependency "minitest"
	spec.add_development_dependency "unicorn"
end
