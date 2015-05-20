#
# Enumeration Sensitive information audit module.
#
# @author Tasos "Zapotek" Laskos <tasos.laskos@gmail.com>
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
        return if !url.downcase.match(/(id|ID)=\d*/)
        print_status "The current URL is #{url}"
        http.get( url, cookies: {}, no_cookie_jar: true ) do |res|
            ["recording","OKOKOK","status:","FAILCode"].each {|item|
                if res.body.include?(item)
                    issue_url = res.effective_url
                    page = res.is_a?( Page ) ? res : res.to_page
                    log_issue(
                       vector: Element::Server.new( page.url ),
                       page:   page
                    )
                    print_ok( "Found issue at #{url}" )
					          audited(url)
                else
                   check_sensitive_res(res.location) if res.location != nil
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
            references:  {
                'OWASP' => 'http://www.owasp.org/'
            },
            targets:     %w(General PHP Java dotNET libXML2),
            issue:       {
                name:            %q{Enumeration sensitive data},
                description:     %q{Enumeration Sensitive information},
                tags:            %w(Enumeration Sensitive),
                cwe:             '',
                severity:        Severity::MEDIUM,
                remedy_guidance: '',
				        verification: true
            }
        }
    end

end
