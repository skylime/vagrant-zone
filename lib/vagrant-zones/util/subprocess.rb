require 'open3'
module VagrantPlugins
  module ProviderZone
    module Util
      class Subprocess
        def initialize(cmd, &block)
          Open3.popen3(cmd) do |_stdin, stdout, stderr, thread|
            # read each stream from a new thread
            { out: stdout, err: stderr }.each do |key, stream|
              stream.each_line do |line|
                if key == :out
                  yield line, nil, thread if block_given?
                elsif key == :err
                  yield nil, line, thread if block_given?
                end
              end
            end
            thread.join # don't exit until the external process is done

            thread.value
          end
        end
      end
    end    
  end
end
