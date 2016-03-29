#
# Enumeration Sensitive information audit module.
#
# @author drewz <drewz.lin@outlook.com>
#
# @version 0.1.2
#
class Arachni::Checks::EnumerationIssue < Arachni::Check::Base

   def run
      # request page without cookies, simulating a logged-out user
      url = page.url
      check_sensitive_res(url)
   end

    def check_sensitive_res(url)
        return if audited?(url)
        return if !url.downcase.match(/(id|ID|key)=\d*/)
        print_status "The current URL is #{url}"
        http.get( url, cookies: {}, no_cookie_jar: true ) do |res|
            ["recording","OKOKOK","status:","FAILCode","OTHER"].each {|item|
                if res.body.include?(item)
                    page = res.is_a?( Page ) ? res : res.to_page
                    log(
                         vector: Element::Path.new( page.url ),
                         proof:  page.response.status_line,
                         page: page
                         )
                    print_ok( "Found issue at #{url}" )
					          audited(url)
                end
            }
        end
		audited(url)
    end


    def self.info
        {
            name:        'Enumeration Sensitive data',
            description: %q{Enumeration Sensitive ID},
            elements:    [Element::Link],
            author:      'TCS  <TCS@gmail.com>',
            version:     '0.1.2',

            issue:       {
                name:            %q{Enumeration sensitive data},
                description:     %q{Enumeration Sensitive information},
                references:  {
                     'OWASP' => 'http://www.owasp.org/'
                },
                tags:            %w(Enumeration Sensitive),
                severity:        Severity::MEDIUM,
                remedy_guidance: ''
            }
        }
    end

end
