# frozen_string_literal: true

require 'open3'
require 'log4r'
module VagrantPlugins
  module ProviderZone
    module Util
      # Class to assist in running a process asychronosly if neccessary
      class Subprocess
        def initialize(cmd, _&block)
          Open3.popen3(cmd) do |_stdin, stdout, stderr, thread|
            # read each stream from a new thread
            { :out => stdout, :err => stderr }.each do |key, stream|
              Thread.new do
                until (line = stream.gets).nil? 
                  # yield the block depending on the stream
                  if key == :out
                    yield line, nil, thread if block_given?
                  elsif block_given?
                    yield nil, line, thread
                  end
                end
              end
            end
            thread.join # don't exit until the external process is done
          end
        end
      end
    end 
  end
end
