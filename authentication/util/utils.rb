require 'securerandom'

class Utils

  def self.generate_session_id
    SecureRandom.hex(20)
  end

end