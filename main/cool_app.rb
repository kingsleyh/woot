require 'sinatra/base'

class CoolApp < Sinatra::Application

  get '/' do
    send_file File.join(settings.public_folder, 'app/index.html')
  end

end

