require 'omniauth'
require 'jwt'

module OmniAuth
  module Strategies
    # handling the jwt request
    class JWT
      class ClaimInvalid < StandardError; end

      include OmniAuth::Strategy

      args [:secret]

      option :secret, nil
      option :algorithm, 'HS256'
      option :uid_claim, 'email'
      option :required_claims, %w[name email]
      option :info_map, 'name' => 'name', 'email' => 'email'
      option :auth_url, nil
      option :valid_within, nil

      def request_phase
        redirect options.auth_url
      end

      def decoded
        raise ClaimInvalid, 'missing location id' unless location_id.present?
        @decoded ||= decoded_token
        check_validity
        @decoded
      end

      def check_validity
        (options.required_claims || []).each do |field|
          check_field_validity(field)
        end
        if options.valid_within && !@decoded['iat']
          raise ClaimInvalid, "Missing required 'iat' claim."
        end
        raise ClaimInvalid, "'iat' timestamp expired." if token_expired
      end

      def check_field_validity(field)
        unless @decoded.key?(field.to_s)
          raise ClaimInvalid, "Missing required '#{field}' claim."
        end
        val = @decoded[field.to_s]
        raise ClaimInvalid, "#{field} cannot be blank." if val.blank?
      end

      def token_expired
        options.valid_within &&
          (Time.now.to_i - @decoded['iat']).abs > options.valid_within
      end

      def location_id
        request.params['location_id']
      end

      def decoded_token
        ::JWT.decode(
          request.params['jwt'],
          # each location has a different secret
          options.secret[location_id],
          options.algorithm
        ).reduce(&:merge)
      end

      def callback_phase
        super
      rescue ClaimInvalid => e
        env['omniauth.origin'] = request.params['origin']
        fail! :claim_invalid, e
      end

      uid { decoded[options.uid_claim] }

      extra do
        { raw_info: decoded }
      end

      info do
        options.info_map.each_with_object({}) do |(k, v), h|
          h[k.to_s] = decoded[v.to_s]
        end
      end
    end

    class Jwt < JWT; end
  end
end
