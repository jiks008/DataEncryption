Pod::Spec.new do |s|
          #1.
          s.name               = "DataEncryption"
          #2.
          s.version            = "1.0.2"
          #3.  
          s.summary         = "DataEncryption framework"
          #4.
          s.homepage        = "http://www.highq.com"
          #5.
          s.license              = "MIT"
          #6.
          s.author               = "jiks"
          #7.
          s.platform            = :ios
          #8.
          s.source              = { :git => "https://github.com/jiks008/DataEncryption.git", :tag => s.version }
          #9.
          s.source_files     = "DataEncryption", "DataEncryption/**/*.{h,m,swift}"
end