# vim: et sw=2 ts=2 sts=2

require File.expand_path("spec_helper", File.dirname(__FILE__))

include Cae::Aws::Signer::Util

describe Cae::Aws::Signer::Util do

  describe "#date_from_headers" do
    it "should parse from an x-amz-date header " do
      date_from_headers('x-amz-date' => 'Wed, 01 Mar 2006 12:00:00 GMT').must_equal '20060301T120000Z'
      date_from_headers('x-amz-date' => '20060301T120000Z').must_equal '20060301T120000Z'
    end

    it "should parse from a Date header" do
      date_from_headers('date' => 'Wed, 01 Mar 2006 12:00:00 GMT').must_equal '20060301T120000Z'
      date_from_headers('date' => '20060301T120000Z').must_equal '20060301T120000Z'
    end

    it "should prefer x-amz-date over date" do
      date_from_headers('date' => '20151021T120000Z', 'x-amz-date' => '20060301T120000Z').must_equal '20060301T120000Z'
    end

    it "should raise when no date is supplied" do
      proc{date_from_headers({})}.must_raise Cae::Aws::Signer::MissingDateError
    end
  end

  describe "#parse_authorization_header" do
    it "should parse a well-formed header" do
      d = parse_authorization_header("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class, Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
      d.must_respond_to :[]
      d[:access_key].must_equal 'AKIAIOSFODNN7EXAMPLE'
      d[:date].must_equal '20130524'
      d[:region].must_equal 'us-east-1'
      d[:service].must_equal 's3'
      d[:signed_headers].must_equal 'content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class'
      d[:signature].must_equal '4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9'
    end

    it "should return nil for bogus data" do
      parse_authorization_header('AWS4-HMAC-SHA256 FOO').must_equal nil
    end
  end

  describe "#parse_chunk_header" do
    it "should parse a well-formed header" do
      s, d = parse_chunk_header("4;chunk-signature=ABCD\r\nDATA\r\n")
      s.must_equal 'ABCD'
      d.must_equal 'DATA'

      s, d = parse_chunk_header("A;chunk-signature=ABCD\r\nDATADATADA\r\n")
      s.must_equal 'ABCD'
      d.must_equal 'DATADATADA'
    end

    it "should raise on invalid headers" do
      parse_chunk_header("BORK").must_equal nil
      parse_chunk_header("1;chunk-signature=A").must_equal nil
      parse_chunk_header("1;chunk-signature=X\r\nD").must_equal nil
      parse_chunk_header("FOO;chunk-signature=ABCD\r\nD\r\n").must_equal nil
      parse_chunk_header("1;sig=ABCD\r\nD\r\n").must_equal nil
    end
  end

  describe "#normalise_headers" do
    it "should convert underscores to dashes" do
      normalise_headers(
        'test_header' => ''
      ).must_equal('test-header' => '')
    end

    it "should strip HTTP_ prefixes" do
      normalise_headers(
        'HTTP_test' => ''
      ).must_equal('test' => '')
    end

    it "should not strip HTTP found anywhere else" do
      normalise_headers(
        'test_HTTP_test' => ''
      ).must_equal('test-http-test' => '')
    end

    it "should lowercase headers" do
      normalise_headers(
        'content-encoding' => 'aws-chunked,gzip',
        'HOST' => 'foo.bar.com'
      ).must_equal(
        'content-encoding' => 'aws-chunked,gzip',
        'host' => 'foo.bar.com'
      )
    end
  end

  describe "#chunked?" do
    it "should detect a chunked header" do
      chunked?(
        'content-encoding' => 'aws-chunked,gzip'
      ).must_equal true
    end
    it "should detect a non-chunked header" do
      chunked?(
        'content-encoding' => 'gzip'
      ).must_equal false
    end
  end

  describe "#uri_encode" do
    it "should handle basic characters" do
      uri_encode('abc').must_equal('abc')
      uri_encode('/').must_equal('%2F')
      uri_encode('"').must_equal('%22')
    end

    it "should handle slash specially when requested" do
      uri_encode('a/a', encode_slash: false).must_equal('a/a')
    end

    it "should handle UTF-8" do
      uri_encode('ç').must_equal('%C3%A7')
      uri_encode('£').must_equal('%C2%A3')
    end
  end

end
