=begin
    Copyright 2010-2015 Tasos Laskos <tasos.laskos@arachni-scanner.com>

    This file is part of the Arachni Framework project and is subject to
    redistribution and commercial restrictions. Please see the Arachni Framework
    web site for more information on licensing and terms of use.
=end

module Arachni
module Element::Capabilities
module Analyzable

# Looks for specific substrings or patterns in response bodies.
#
# @author Tasos "Zapotek" Laskos <tasos.laskos@arachni-scanner.com>
module Signature

    SIGNATURE_CACHE   = {
        match: Support::Cache::LeastRecentlyPushed.new( 10_000 )
    }

    SIGNATURE_OPTIONS = {
        # The regular expression to match against the response body.
        #
        # Alternatively, you can use the :substring option.
        regexp:    nil,

        # The substring to look for the response body.
        #
        # Alternatively, you can use the :regexp option.
        substring: nil,

        # Array of patterns to ignore.
        #
        # Useful when needing to narrow down what to log without
        # having to construct overly complex match regexps.
        ignore:    nil,

        # Extract the longest word from each regexp and only proceed to the
        # full match only if that word is included in the response body.
        #
        # The check is case insensitive.
        longest_word_optimization: false
    }

    # Performs signatures analysis and logs an issue should there be one.
    #
    # It logs an issue when:
    #
    # * `:match` == nil AND `:regexp` matches the response body
    # * `:match` != nil AND  `:regexp` match == `:match`
    # * `:substring` exists in the response body
    #
    # @param  [String, Array<String>, Hash{Symbol => <String, Array<String>>}]  payloads
    #   Payloads to inject, if given:
    #
    #   * {String} -- Will inject the single payload.
    #   * {Array} -- Will iterate over all payloads and inject them.
    #   * {Hash} -- Expects {Platform} (as `Symbol`s ) for keys and {Array} of
    #       `payloads` for values. The applicable `payloads` will be
    #       {Platform::Manager#pick picked} from the hash based on
    #       {Element::Capabilities::Submittable#platforms applicable platforms}
    #       for the {Element::Capabilities::Submittable#action resource} to be audited.
    # @param  [Hash]    opts
    #   Options as described in {Arachni::Check::Auditor::OPTIONS} and
    #   {SIGNATURE_OPTIONS}.
    #
    # @return   [Bool]
    #   `true` if the audit was scheduled successfully, `false` otherwise (like
    #   if the resource is out of scope).
    def signature_analysis( payloads, opts = { } )
        return false if self.inputs.empty?

        if scope.out?
            print_debug 'Signature analysis: Element is out of scope,' <<
                            " skipping: #{audit_id}"
            return false
        end

        # Buffer possible issues, we'll only register them with the system once
        # we've evaluated our control response.
        @candidate_issues = []

        # Perform the analysis.
        opts = self.class::OPTIONS.merge( SIGNATURE_OPTIONS.merge( opts ) )
        audit( payloads, opts ) { |response| get_matches( response ) }
    end

    private

    # Tries to identify an issue through pattern matching.
    #
    # If a issue is found a message will be printed and the issue will be logged.
    #
    # @param  [HTTP::Response]  response
    def get_matches( response )
        vector = response.request.performer
        opts   = vector.audit_options.dup
        opts[:substring] = vector.seed if !opts[:regexp] && !opts[:substring]

        match_patterns( opts[:regexp], method( :match_regexp_and_log ), response, opts.dup )
        match_patterns( opts[:substring], method( :match_substring_and_log ), response, opts.dup )
    end

    def match_patterns( patterns, matcher, response, opts )
        k = [patterns, response.body]
        return if SIGNATURE_CACHE[:match][k] == false

        if opts[:longest_word_optimization]
            opts[:downcased_body] = response.body.downcase
        end

        case patterns
            when Regexp, String, Array
                [patterns].flatten.compact.each do |pattern|
                    res = matcher.call( pattern, response, opts )
                    SIGNATURE_CACHE[:match][k] ||= !!res
                end

            when Hash
                if opts[:platform] && patterns[opts[:platform]]
                    [patterns[opts[:platform]]].flatten.compact.each do |p|
                        [p].flatten.compact.each do |pattern|
                            res = matcher.call( pattern, response, opts )
                            SIGNATURE_CACHE[:match][k] ||= !!res
                        end
                    end

                else
                    patterns.each do |platform, p|
                        dopts = opts.dup
                        dopts[:platform] = platform

                        [p].flatten.compact.each do |pattern|
                            res = matcher.call( pattern, response, dopts )
                            SIGNATURE_CACHE[:match][k] ||= !!res
                        end
                    end
                end

                return if !opts[:payload_platforms]

                # Find out if there are any patterns without associated payloads
                # and match them against every payload's response.
                patterns.select { |p, _|  !opts[:payload_platforms].include?( p ) }.
                    each do |platform, p|
                        dopts = opts.dup
                        dopts[:platform] = platform

                        [p].flatten.compact.each do |pattern|
                            res = matcher.call( pattern, response, dopts )
                            SIGNATURE_CACHE[:match][k] ||= !!res
                        end
                    end
        end
    end

    def match_substring_and_log( substring, response, opts )
        return if substring.to_s.empty?

        k = [substring, response.body]
        return if SIGNATURE_CACHE[:match][k] == false

        SIGNATURE_CACHE[:match][k] = includes = response.body.include?( substring )
        return if !includes || ignore?( response, opts )

        @candidate_issues << {
            response:  response,
            platform:  opts[:platform],
            proof:     substring,
            signature: substring,
            vector:    response.request.performer
        }
        setup_verification_callbacks

        true
    end

    def match_regexp_and_log( regexp, response, opts )
        k = [regexp, response.body]
        return if SIGNATURE_CACHE[:match][k] == false

        regexp = regexp.is_a?( Regexp ) ? regexp :
            Regexp.new( regexp.to_s, Regexp::IGNORECASE )

        if opts[:downcased_body]
            return if !opts[:downcased_body].include?( longest_word_for_regexp( regexp ) )
        end

        match_data = response.body.match( regexp )
        return if !match_data

        match_data = match_data[0].to_s

        SIGNATURE_CACHE[:match][k] = !match_data.empty?

        return if match_data.empty? || ignore?( response, opts )

        @candidate_issues << {
            response:  response,
            platform:  opts[:platform],
            proof:     match_data,
            signature: regexp,
            vector:    response.request.performer
        }
        setup_verification_callbacks

        true
    end

    def ignore?( res, opts )
        [opts[:ignore]].flatten.compact.each do |r|
            r = r.is_a?( Regexp ) ? r : Regexp.new( r.to_s, Regexp::IGNORECASE )
            return true if res.body.scan( r ).flatten.first
        end
        false
    end

    def setup_verification_callbacks
        return if @setup_verification_callbacks
        @setup_verification_callbacks = true

        # Go over the issues to ensure that the signature that identified them
        # does not match by default.
        http.after_run do
            @setup_verification_callbacks = false
            next if @candidate_issues.empty?

            # Grab the default response.
            submit do |response|
                # Something has gone wrong, timed-out request or closed connection.
                # If we can't verify the issue bail out...
                next if response.code == 0

                while (issue = @candidate_issues.pop)
                    # If the body of the control response matches the proof
                    # of the current issue don't bother, it'll be a coincidence
                    # causing a false positive.
                    next if response.body.include?( issue[:proof] )

                    @auditor.log( issue )
                end
            end
        end
    end

    def longest_word_for_regexp( regexp )
        @@longest_word_for_regex ||= {}
        @@longest_word_for_regex[regexp.source.hash] ||=
            regexp.source.longest_word.downcase
    end

end
end
end
end
