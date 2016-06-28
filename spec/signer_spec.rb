# vim: et sw=2 ts=2 sts=2

require File.expand_path("spec_helper", File.dirname(__FILE__))

require 'unicorn'

describe Cae::Aws::Signer do

  # Test with each .sreq
  Dir[File.dirname(__FILE__) + '/aws4_testsuite/*.sreq'].each do |sreq|
    it "should handle #{File.basename sreq}" do
      # these don't parse as HTTP requests properly
      skip if File.basename(sreq) == 'post-vanilla-query-nonunreserved.sreq'
      skip if File.basename(sreq) == 'post-vanilla-query-space.sreq'

      input = File.read sreq

      parser = Unicorn::HttpParser.new
      parser.buf << input

      parser.parse

      headers = parser.env.
        select{|k,v| k.start_with?('HTTP_') || k == 'CONTENT_TYPE' }.
        collect{|pair| [pair[0].sub(/^HTTP_/, ''), pair[1]] }.to_h

      signer = Cae::Aws::Signer.new({
        secret_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        method: parser.env['REQUEST_METHOD'],
        uri: "http://#{parser.env['HTTP_HOST']}#{parser.env['REQUEST_URI']}",
        headers: parser.env,
        body: parser.buf[0, parser.env['CONTENT_LENGTH'].to_i],
      })


      check_creq = File.read(sreq.gsub(/sreq$/, 'creq')).gsub(/\r\n/, "\n")
      check_creq.must_equal signer.canonical_request

      check_sts = File.read(sreq.gsub(/sreq$/, 'sts')).gsub(/\r\n/, "\n")
      check_sts.must_equal signer.string_to_sign

      signer.verify.must_equal true

    end
  end

  # streaming support
  Dir[File.dirname(__FILE__) + '/streaming_testsuite/*.sreq'].each do |sreq|
    it "works with streaming request #{sreq}" do
      input = File.read sreq

      parser = Unicorn::HttpParser.new
      parser.buf << input

      parser.parse

      headers = parser.env.
        select{|k,v| k.start_with?('HTTP_') || k == 'CONTENT_TYPE' || k == 'CONTENT_LENGTH' }.
        collect{|pair| [pair[0].sub(/^HTTP_/, ''), pair[1]] }.to_h

      signer = Cae::Aws::Signer.new({
        secret_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        method: parser.env['REQUEST_METHOD'],
        uri: "http://#{parser.env['HTTP_HOST']}#{parser.env['REQUEST_URI']}",
        headers: parser.env
      })

      # chomp is easier than keeping trailing linefeed out of file
      check_creq = File.read(sreq.gsub(/sreq$/, 'creq')).chomp
      check_creq.must_equal signer.canonical_request

      # chomp is easier than keeping trailing linefeed out of file
      check_sts = File.read(sreq.gsub(/sreq$/, 'sts')).chomp
      check_sts.must_equal signer.string_to_sign

      signer.verify.must_equal true

      # now start sending data chunks and verify those signatures
      chunk = [
        "10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
        "a" * 65536
      ].join("\r\n")
      signer.verify_chunk(chunk).must_equal true

      chunk = [
        "400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
        "a" * 1024
      ].join("\r\n")
      signer.verify_chunk(chunk).must_equal true

      chunk = [
        "0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
        ""
      ].join("\r\n")
      signer.verify_chunk(chunk).must_equal true


    end
  end

end
