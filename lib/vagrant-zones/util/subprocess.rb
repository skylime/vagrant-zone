require 'open3'

module VagrantPlugins
  module ProviderZone
    module Utils
      class Subprocess
        def initialize(cmd, &block)
          Open3.popen3(cmd) do |stdin, stdout, stderr, thread|
            # read each stream from a new thread
            { :out => stdout, :err => stderr }.each do |key, stream|
              Thread.new do
                until (line = stream.gets).nil? do
                  # yield the block depending on the stream
                  if key == :out
                    yield line, nil, thread if block_given?
                  else
                    yield nil, line, thread if block_given?
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
