require 'sinatra/base'

class CoolApp < Sinatra::Application

  get '/' do
    'hi'
  end

end

