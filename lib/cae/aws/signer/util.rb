# vim: et sw=2 ts=2 sts=2

require 'cgi'
require 'set'
require 'openssl'

module Cae
  module Aws
    class Signer
      module Util

        HMAC_CIPHER = 'sha256'.freeze

        # Regexp to apply to chunk headers
        CHUNK_HEADER_RE = %r{\A((\h+);chunk-signature=(\h+)\r\n)}.freeze

        # Regexp to apply to an Authorization header to capture component parts
        AUTHORIZATION_HEADER_RE = %r{\AAWS4-HMAC-SHA256 +Credential=(?<access_key>[^/]+)/(?<date>[^/]+)/(?<region>[^/]+)/(?<service>[^/]+)/aws4_request, *SignedHeaders=(?<signed_headers>[^,]+), *Signature=(?<signature>\h{64})\Z}.freeze

        # Captures from {AUTHORIZATION_HEADER_RE} are placed into this struct;
        # order of struct members must match above regexp capture order!
        AuthData = Struct.new(:access_key, :date, :region, :service, :signed_headers, :signature).freeze

        # A +Set+ of characters which {#uri_encode} should never encode.
        # This does not include / which is selectively disabled.
        NEVER_ENCODE = Set.new([*0..9, *'A'..'Z', *'a'..'z', '-', '.', '_', '~', '%']).freeze

        # Normalise a hash of headers into signed_header format
        # * remove HTTP_ prefix
        # * lowercase
        # * convert _ into -
        #
        # * HTTP_HOST -> host
        # * CONTENT_LENGTH -> content-length
        #
        def normalise_headers(headers)
          headers.map do |k, v|
            [ k.sub(/^HTTP_/, '').downcase.tr('_', '-'), v ]
          end.to_h
        end

        def date_from_headers(headers)
          # x-amz-date header takes preference as per Amazon spec.
          hdr = headers['x-amz-date'] || headers['date']

          raise MissingDateError unless hdr

          # parse into 20110909T233600Z
          Time.parse(hdr).strftime('%Y%m%dT%H%M%SZ')
        end

        # Split an Authorization header into its component parts,
        # returning them in a struct we can use member lookup on.
        def parse_authorization_header(header)
          return nil unless md = header.match(AUTHORIZATION_HEADER_RE)
          AuthData.new(*md.captures)
        end

        def parse_chunk_header(chunk)
          return nil unless chunk =~ CHUNK_HEADER_RE
          [ $3, chunk[$1.length, $2.to_i(16)] ]
        end

        # return true if the passed headers hash indicates a Chunked Upload
        # ('aws-chunked' is found in the Content-Encoding header)
        def chunked?(headers)
          content_encoding = headers['content-encoding'] || ''
          content_encoding.split(',').include?('aws-chunked')
        end

        # Shortcut to our HMAC digest generation
        def hmac(key, data)
          OpenSSL::HMAC.digest(HMAC_CIPHER, key, data)
        end

        # Shortcut to our HMAC hexdigest generation
        def hexhmac(key, data)
          OpenSSL::HMAC.hexdigest(HMAC_CIPHER, key, data)
        end

        # Create a SHA256 hexdigest of the given data
        def hexdigest(data)
          OpenSSL::Digest::SHA256.new(data).hexdigest
        end

        # Amazon-compliant uri_encode.
        def uri_encode(str, encode_slash: true)
          str.each_char.map do |c|
            if NEVER_ENCODE.include?(c)
              c
            elsif c == '/'.freeze
              # CGI.escape('/') => '%2F' # (hardcoding is an optimisation)
              encode_slash ? '%2F'.freeze : '/'.freeze
            else
              # check this encodes everything?
              ::CGI.escape(c)
            end
          end.join
        end

      end
    end
  end
end
