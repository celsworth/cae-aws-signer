# vim: et sw=2 ts=2 sts=2

require 'cae/aws/signer/util'
require 'cae/aws/signer/version'

require 'pathname'
require 'openssl'
require 'uri'

module Cae
  module Aws
    class Signer

      # Pull in stateless helper methods.
      # They're split out to make unit testing easier.
      include Util

      LF = "\n".freeze
      SLASH = '/'.freeze

      # StringToSign on a chunked request uses this, but it never changes
      # so we can pre-compute it as a time-saver.
      EMPTY_STRING_HEXDIGEST = OpenSSL::Digest::SHA256.new('').hexdigest.freeze

      # A +Set+ of characters which {#uri_encode} should never encode.
      # This does not include / which is selectively disabled.
      NEVER_ENCODE = Set.new([*0..9, *'A'..'Z', *'a'..'z', '-', '.', '_', '~', '%']).freeze

      class Error < StandardError; end

      # Error raised if an unsupported algorithm is passed in
      class AlgorithmError < Error; end

      # Error raised on any other non-specific input error
      class AuthorizationError < Error; end

      class UnsupportedAuthError < Error; end

      class MissingDateError < Error; end
      class MissingAuthorizationError < Error; end


      # Initialise a new SignatureVerifier.
      #
      # @param secret_key [String] Shared secret key
      # @param method [String] Request method; GET / POST etc
      # @param uri [String] Complete URI of the request
      # @param headers [Hash] Request headers. This will be normalised so
      #                you can just pass in +request.env+
      # @param body [String] Request body. For chunked requests, omit this
      def initialize(secret_key:, method:, uri:, headers:, body: nil)
        @secret_key = secret_key

        @method = method.upcase
        @uri = URI(uri)
        @body = body

        @headers = normalise_headers(headers)

        # parse Authorization header, which must be present
        fail MissingAuthorizationError unless @headers['authorization']

        # we only support v4, not v2 (identified by 'AWS ')
        fail UnsupportedAuthError if @headers['authorization'][0, 4] == 'AWS '

        @authorization = parse_authorization_header(@headers['authorization'])

        # error parsing Authorization string (not AWS4? maybe its 2?)
        fail AuthorizationError unless @authorization


        # split signed_headers on ; into an array of headers
        @signed_headers = @authorization[:signed_headers].split(';')

        fail MissingDateError unless @date = date_from_headers(@headers)

      end

      def verify
        signature = hexhmac(signing_key(@secret_key), string_to_sign)

        # remember what we've calculated in case we're a chunked upload
        @previous_signature = signature

        signature == @authorization[:signature]
      end

      def verify_chunk(chunk)
        # parse the first line of the chunk:
        # string(hex(chunk-size)) + ";chunk-signature=" + signature + \r\n
        expected_signature, data = parse_chunk_header(chunk)

        sk = signing_key(@secret_key)
        sts = chunked_string_to_sign(data)
        chunk_signature = hexhmac(sk, sts)

        # prepare for the next chunk by remembering this signature
        @previous_signature = chunk_signature

        chunk_signature == expected_signature
      end


      # Generate a StringToSign for a chunk piece.
      def chunked_string_to_sign(chunk_data)
        parts = []
        parts << 'AWS4-HMAC-SHA256-PAYLOAD'
        parts << @date
        parts << credential_string
        parts << @previous_signature
        parts << EMPTY_STRING_HEXDIGEST
        parts << hexdigest(chunk_data)
        parts.join(LF)
      end

      # Generate a StringToSign for a precomputed checksum.
      def string_to_sign
        parts = []
        parts << 'AWS4-HMAC-SHA256'
        parts << @date
        parts << credential_string
        parts << hexdigest(canonical_request)
        parts.join(LF)
      end

      def credential_string
        parts = []
        parts << @date[0, 8]
        parts << @authorization[:region]
        parts << @authorization[:service]
        parts << 'aws4_request'
        parts.join(SLASH)
      end

      # Calculate a signing_key from a given secret, and our scope.
      def signing_key(secret)
        kDate = hmac('AWS4' + @secret_key, @date[0, 8])
        kRegion = hmac(kDate, @authorization[:region])
        kService = hmac(kRegion, @authorization[:service])
        hmac(kService, 'aws4_request')
      end

      # Build a CanonicalRequest.
      #
      # For chunked requests, this does not have the payload in it.
      # Otherwise, +payload+ should be the payload to use.
      def canonical_request
        parts = []
        parts << @method
        parts << canonical_uri
        parts << canonical_query_string
        parts << canonical_headers
        parts << @signed_headers.join(';')

        # need to check how to handle STREAMING-AWS4-HMAC-SHA256-PAYLOAD
        if @headers['x-amz-content-sha256']
          parts << @headers['x-amz-content-sha256']
        else
          # not sure this will ever be used? is x-amz-content-sha256 mandatory?
          parts << hexdigest(@body || '')
        end
        parts.join(LF)
      end

      # Build a CanonicalURL string from our +uri+.
      def canonical_uri
        pn = Pathname.new(@uri.path).cleanpath.to_s
        pn << SLASH if @uri.path.length > 1 and @uri.path[-1] == SLASH
        pn.gsub!(%r{//}, SLASH)
        uri_encode(pn, encode_slash: false)
      end

      # Build a CanonicalQueryString from our +uri+.
      def canonical_query_string
        @uri.query.to_s.split('&').sort.map do |p|
          k, v = p.split('=')
          uri_encode(k) + '=' + uri_encode(v)
        end.join('&')
      end

      # Build a CanonicalHeaders string.
      def canonical_headers
        @signed_headers.map do |header|
          value = @headers[header]
          # sort all header values except Authorization and Date
          unless %w(authorization date).include?(header)
            value = value.split(',').sort.join(',')
          end
          [header, value.strip].join(':')
        end.join(LF) + LF
      end

    end
  end
end
