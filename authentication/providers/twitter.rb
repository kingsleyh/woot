require 'totally_lazy'
require 'Oj'

class Twitter

  def self.info(data)
    Oj.dump({
        provider: option(data.provider).get_or_else(''),
        uid: option(data.uid).get_or_else(''),
        token: option(data.credentials.token).get_or_else(''),
        secret: option(data.credentials.secret).get_or_else(''),
        description: option(data.extra.raw_info.description).get_or_else(''),
        full_name: option(data.extra.raw_info.name).get_or_else(''),
        screen_name: option(data.extra.raw_info.screen_name).get_or_else(''),
        image: option(data.extra.raw_info.profile_image_url).get_or_else(''),
    })

  end

end