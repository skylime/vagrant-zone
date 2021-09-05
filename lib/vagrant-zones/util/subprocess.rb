# frozen_string_literal: true

require 'open3'
require "log4r"
module VagrantPlugins
  module ProviderZone
    module Util
      # This is a utlity to start a subprocess
      class Subprocess
        def initialize(cmd, &block)
          Open3.popen3(cmd) do |_stdin, stdout, stderr, thread|
            # read each stream from a new thread
            { :out => stdout, :err => stderr }.each do |key, stream|
              Thread.new do
                until (line = stream.gets).nil? do
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
