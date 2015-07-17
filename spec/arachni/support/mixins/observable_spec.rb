require 'spec_helper'

class ObservableTest
    include Arachni::Support::Mixins::Observable

    public :clear_observers

    advertise :my_event, :my_other_event

    def notify( event, *args )
        send "notify_#{event}", *args
    end

end

describe Arachni::Support::Mixins::Observable do

    subject{ ObservableTest.new }

    describe '#<event>' do
        it 'adds an observer' do
            called = false
            subject.my_event { called = true }
            subject.notify :my_event

            called.should be_true
        end

        it 'returns self' do
            subject.my_event { }.should == subject
        end

        context 'when no block is given' do
            it 'raises ArgumentError' do
                expect { subject.my_event }.to raise_error ArgumentError
            end
        end

        context 'when the observer expects arguments' do
            it 'forwards them' do
                received_args = nil
                sent_args     = [ 1, 2, 3]

                subject.my_other_event do |one, two, three|
                    received_args = [one, two, three]
                end
                subject.notify :my_other_event, sent_args

                received_args.should == sent_args
            end
        end

        describe 'when the event does not exist' do
            it "raises #{NoMethodError}" do
                expect { subject.blah_event }.to raise_error NoMethodError
            end
        end
    end

    describe '#notify' do
        it 'returns nil' do
            subject.my_event { }
            subject.notify( :my_event ).should be_nil
        end

        context 'when a callback raises an exception' do
            it 'does not affect other callbacks' do
                called = []

                subject.my_event { called << 1 }
                subject.my_event { called << 2; raise }
                subject.my_event { called << 3 }

                subject.notify( :my_event )

                called.should == [1, 2, 3]
            end
        end
    end

    describe '#clear_observers' do
        it 'removes all observers' do
            called = false

            subject.my_event { called = true }
            subject.clear_observers

            subject.notify :my_event

            called.should be_false

        end
    end

end
