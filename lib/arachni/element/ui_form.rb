=begin
    Copyright 2010-2015 Tasos Laskos <tasos.laskos@arachni-scanner.com>

    This file is part of the Arachni Framework project and is subject to
    redistribution and commercial restrictions. Please see the Arachni Framework
    web site for more information on licensing and terms of use.
=end

require_relative 'base'

module Arachni::Element

# @author Tasos "Zapotek" Laskos <tasos.laskos@arachni-scanner.com>
class UIForm < Base
    require_relative 'ui_form/dom'

    include Arachni::Element::Capabilities::DOMOnly

    SUPPORTED_TYPES = Set.new([:input, :button])

    attr_accessor :opening_tags

    def initialize( options )
        super options

        @opening_tags = (options[:opening_tags] || []).dup
    end

    def dup
        super.tap do |o|
            o.opening_tags = self.opening_tags.dup
        end
    end

    def self.type
        :ui_form
    end

    def self.from_browser( browser, page )
        ui_forms = []

        # JS not supported on page, no sense in continuing...
        return ui_forms if !browser.javascript.supported?

        # Does the page have any buttons at all?
        if !page.has_elements?( :button ) &&
            !page.document.xpath( "//input[@type='button']" )&&
            !page.document.xpath( "//input[@type='submit']" )
            return ui_forms
        end

        # Does the page have any text inputs?
        inputs, opening_tags = inputs_from_page( page )
        return ui_forms if inputs.empty?

        # Looks like we have input groups, get buttons with events.
        browser.each_element_with_events false do |locator, events|
            next if !SUPPORTED_TYPES.include?( locator.tag_name )
            next if locator.tag_name == :input &&
                locator.attributes['type'] != 'button' &&
                locator.attributes['type'] != 'submit'

            browser.filter_events( locator.tag_name, events ).each do |event, _|
                ui_forms << new(
                    action:       page.url,
                    source:       locator.to_s,
                    method:       event,
                    inputs:       inputs,
                    opening_tags: opening_tags
                )
            end
        end

        ui_forms
    end

    def self.inputs_from_page( page )
        opening_tags = {}
        inputs       = {}

        page.document.css( 'textarea' ).each do |textarea|
            name = node_to_name( textarea )

            inputs[name]       = textarea.text
            opening_tags[name] = Arachni::Browser::ElementLocator.from_node( textarea ).to_s
        end

        page.document.css( 'input' ).each do |input|
            next if input['type'] && input['type'] != 'text'

            name = node_to_name( input )

            inputs[name]       = input['value'].to_s
            opening_tags[name] = Arachni::Browser::ElementLocator.from_node( input ).to_s
        end

        [inputs, opening_tags]
    end

    def self.node_to_name( node )
        node['name'] || node['id'] ||
            Arachni::Browser::ElementLocator.from_node( node ).to_s
    end

end
end

Arachni::UIForm = Arachni::Element::UIForm
